using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;
namespace EbatVlastey.Core;

public sealed class LoopbackTlsServer : IAsyncDisposable {
    readonly TcpListener listener=new(IPAddress.Loopback,0);
    readonly CancellationTokenSource stop=new();
    readonly X509Certificate2 leaf,ca;
    readonly Task worker;
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    public string? LastFailure {get;private set;}
    public LoopbackTlsServer(X509Certificate2 leaf,X509Certificate2 ca,X509Certificate2 root) {
        this.leaf=leaf; this.ca=ca; _=root;
        listener.Start(); worker=Serve();
    }
    async Task Serve() {
        try {
            while(!stop.IsCancellationRequested) {
                using var client=await listener.AcceptTcpClientAsync(stop.Token);
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(stop.Token); timeout.CancelAfter(TimeSpan.FromSeconds(4));
                using var registration=timeout.Token.Register(client.Dispose);
                try {
                    // Schannel cannot use ephemeral server keys on all Windows builds.
                    // A managed TLS server keeps the test key entirely in memory.
                    var protocol=new TlsServerProtocol(client.GetStream()); protocol.Accept(new VerificationTlsServer(leaf,ca));
                    using var ssl=protocol.Stream; var buffer=new byte[4096]; var read=ssl.Read(buffer,0,buffer.Length); if(read==0) continue;
                    var response=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nOK");
                    ssl.Write(response,0,response.Length); ssl.Flush();
                } catch(Exception ex) when(ex is AuthenticationException or IOException or OperationCanceledException or ObjectDisposedException) { LastFailure=ex.ToString(); }
            }
        } catch(Exception ex) when(ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }
    public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await worker; stop.Dispose(); }
}

sealed class VerificationTlsServer : DefaultTlsServer {
    readonly X509Certificate2 leaf,ca;
    public VerificationTlsServer(X509Certificate2 leaf,X509Certificate2 ca) : base(new BcTlsCrypto(new SecureRandom())) {this.leaf=leaf;this.ca=ca;}
    protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv12];
    protected override int[] GetSupportedCipherSuites() => [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384];
    protected override TlsCredentialedSigner GetRsaSignerCredentials() {
        using var rsa=leaf.GetRSAPrivateKey() ?? throw new InvalidOperationException("Нет временного ключа проверки.");
        var key=DotNetUtilities.GetRsaKeyPair(rsa.ExportParameters(true)).Private;
        var certificates=new Org.BouncyCastle.Tls.Certificate(new TlsCertificate[]{Crypto.CreateCertificate(leaf.RawData),Crypto.CreateCertificate(ca.RawData)});
        return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context),(BcTlsCrypto)Crypto,key,certificates,new SignatureAndHashAlgorithm(Org.BouncyCastle.Tls.HashAlgorithm.sha256,SignatureAlgorithm.rsa));
    }
}

public static class BrowserProbe {
    public static string[] InstalledBrowsers() {
        var candidates=new[] {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),@"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),@"Google\Chrome\Application\chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),@"Microsoft\Edge\Application\msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),@"Microsoft\Edge\Application\msedge.exe")
        };
        return candidates.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).GroupBy(Path.GetFileName).Select(g=>g.First()).ToArray();
    }
    public static async Task Verify(CertificateBundle bundle,Action<string>? report=null) {
        var browsers=InstalledBrowsers();
        if(browsers.Length==0) { report?.Invoke("Chrome и Edge не найдены: проверено только доверие Windows."); return; }
        foreach(var path in browsers) {
            await VerifyBrowser(path,bundle,report);
        }
    }
    public static async Task VerifyBrowser(string path,CertificateBundle bundle,Action<string>? report=null) {
            await using var browser=await CdpBrowser.Start(path);
            foreach(var probe in bundle.Probes.Where(p=>p.Name is not ("signing-no-dns" or "::1" or "2001:db8::1" or "192.0.2.1"))) {
                await using var server=new LoopbackTlsServer(probe.Certificate,bundle.ProbeCa,bundle.Root);
                var host=probe.Name=="mixed-ru-com"?"test.ru":probe.Name;
                var url=$"https://{host}:{server.Port}/{Guid.NewGuid():N}";
                var result=await browser.Navigate(url);
                if(probe.Expected ? result!="OK" : !ConstraintError(result)) throw new InvalidOperationException($"Проверка {Path.GetFileName(path)}: {probe.Name}: {result}");
                report?.Invoke($"{Path.GetFileName(path)}: {probe.Name} — {(probe.Expected?"принят":"отклонён ограничениями")}");
            }
    }
    public static bool ConstraintError(string error) => error is "net::ERR_CERT_INVALID" or "net::ERR_CERT_NAME_CONSTRAINT_VIOLATION";
}

sealed class CdpBrowser : IAsyncDisposable {
    readonly Process process;
    readonly string profile;
    readonly BrowserPipe pipe;
    readonly Queue<JsonElement> events=new();
    string? session;
    int sequence;
    CdpBrowser(Process process,string profile,BrowserPipe pipe) { this.process=process; this.profile=profile; this.pipe=pipe; }
    public static async Task<CdpBrowser> Start(string executable) {
        var profile=Path.Combine(Path.GetTempPath(),"EbatVlastey-Browser-"+Guid.NewGuid().ToString("N"));
        BrowserPipe? pipe=null; CdpBrowser? browser=null;
        try {
            Directory.CreateDirectory(profile); pipe=new BrowserPipe();
            var arguments=new[]{"--headless=new","--remote-debugging-pipe","--remote-debugging-io-pipes="+pipe.ChildHandles,"--user-data-dir="+profile,"--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-sync","--no-proxy-server","--host-resolver-rules=MAP * 127.0.0.1, EXCLUDE localhost","about:blank"};
            var process=BrowserPipeProcess.Start(executable,arguments,pipe.ChildInput,pipe.ChildOutput);
            browser=new CdpBrowser(process,profile,pipe); pipe.StartReading();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(25));
            var targets=await browser.Command("Target.getTargets",new{},timeout.Token);
            var target=targets.GetProperty("targetInfos").EnumerateArray().First(t=>t.GetProperty("type").GetString()=="page").GetProperty("targetId").GetString();
            var attached=await browser.Command("Target.attachToTarget",new{targetId=target,flatten=true},timeout.Token);
            browser.session=attached.GetProperty("sessionId").GetString();
            await browser.Command("Page.enable",new{},timeout.Token); await browser.Command("Network.enable",new{},timeout.Token); return browser;
        } catch {
            if(browser!=null) await browser.DisposeAsync();
            else { if(pipe!=null) await pipe.DisposeAsync(); await DeleteProfile(profile); }
            throw;
        }
    }
    public async Task<string> Navigate(string url) {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12)); events.Clear();
        var response=await Command("Page.navigate",new{url},timeout.Token);
        if(response.TryGetProperty("errorText",out var error)) return error.GetString() ?? "Неизвестная ошибка TLS";
        string? requestId=null;
        while(true) {
            var evt=events.Count>0?events.Dequeue():await Receive(timeout.Token);
            if(!evt.TryGetProperty("method",out var method) || !evt.TryGetProperty("params",out var data)) continue;
            if(method.GetString()=="Network.requestWillBeSent" && data.GetProperty("request").GetProperty("url").GetString()==url) requestId=data.GetProperty("requestId").GetString();
            if(method.GetString()=="Network.responseReceived" && data.GetProperty("response").GetProperty("url").GetString()==url) return data.GetProperty("response").GetProperty("status").GetInt32()==200?"OK":"Неожиданный HTTP-ответ";
            if(method.GetString()=="Network.loadingFailed" && data.GetProperty("requestId").GetString()==requestId) return data.GetProperty("errorText").GetString() ?? "Неизвестная ошибка сети";
        }
    }
    async Task<JsonElement> Command(string method,object parameters,CancellationToken token) {
        var id=++sequence;
        var message=new Dictionary<string,object?>{{"id",id},{"method",method},{"params",parameters}};
        if(session!=null) message["sessionId"]=session;
        await pipe.Send(JsonSerializer.SerializeToUtf8Bytes(message),token);
        while(true) {
            var result=await Receive(token);
            if(result.TryGetProperty("id",out var responseId) && responseId.GetInt32()==id) { if(result.TryGetProperty("error",out var error)) throw new IOException(error.ToString()); return result.GetProperty("result"); }
            if(session!=null && result.TryGetProperty("sessionId",out var source) && source.GetString()==session) events.Enqueue(result);
        }
    }
    Task<JsonElement> Receive(CancellationToken token)=>pipe.Receive(token);
    public async ValueTask DisposeAsync() {
        try { if(!process.HasExited) process.Kill(true); await process.WaitForExitAsync(); } catch(InvalidOperationException) { }
        finally { process.Dispose(); await pipe.DisposeAsync(); await DeleteProfile(profile); }
    }
    static async Task DeleteProfile(string profile) {
        if(!Path.GetFullPath(profile).StartsWith(Path.GetFullPath(Path.GetTempPath()),StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(profile).StartsWith("EbatVlastey-Browser-",StringComparison.Ordinal)) throw new IOException("Недопустимый путь временного профиля.");
        for(var attempt=0;attempt<3;attempt++) try { if(Directory.Exists(profile)) Directory.Delete(profile,true); break; } catch(IOException) { await Task.Delay(200); } catch(UnauthorizedAccessException) { await Task.Delay(200); }
    }
}
