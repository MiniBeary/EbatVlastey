using EbatVlastey.Core;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Net.Sockets;
using System.Formats.Asn1;

if(args.FirstOrDefault()=="--inheritance-child") return BrowserSecurity.CheckInheritedHandle(args[1]);
var failures = 0;
Run("Real Windows name constraints and original public keys", () => {
    using var bundle = CertificateFactory.Generate();
    var allowed = new[]{"test.ru","test.su","test.xn--p1ai","signing-no-dns"};
    Assert(bundle.Probes.Length == 11,"Missing negative cases");
    foreach (var probe in bundle.Probes) {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(bundle.Root);
        chain.ChainPolicy.ExtraStore.Add(bundle.ProbeCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        var accepted = chain.Build(probe.Certificate);
        Assert(accepted == allowed.Contains(probe.Name), $"{probe.Name}: acceptance={accepted}");
        if (!accepted) Assert(chain.ChainStatus.Any(x => x.Status.ToString().Contains("NameConstraint")), "Failure must be a name constraint");
    }
    using var sources = SourceCatalog.Load();
    for(var i=0;i<2;i++) {
        var source = sources.Certificates[i]; var cross = bundle.Crosses[i];
        Assert(source.PublicKey.Oid.Value == cross.PublicKey.Oid.Value && source.PublicKey.EncodedKeyValue.RawData.SequenceEqual(cross.PublicKey.EncodedKeyValue.RawData) && (source.PublicKey.EncodedParameters?.RawData ?? []).SequenceEqual(cross.PublicKey.EncodedParameters?.RawData ?? []), "Original public key changed");
        Assert(source.SubjectName.RawData.SequenceEqual(cross.SubjectName.RawData), "Subject changed");
        Assert(cross.NotAfter <= source.NotAfter && cross.NotAfter <= bundle.Root.NotAfter, "Lifetime exceeds source");
        Assert(!cross.HasPrivateKey && !bundle.Root.HasPrivateKey, "Persistable certificate has private key");
    }
});
Run("Each installation gets a different root", () => {
    using var a = CertificateFactory.Generate(); using var b = CertificateFactory.Generate();
    Assert(a.Root.Thumbprint != b.Root.Thumbprint, "Roots reused");
});
Run("Loopback TLS sends the verification certificate and chain", () => {
    using var bundle=CertificateFactory.Generate();
    var server=new LoopbackTlsServer(bundle.Probes[0].Certificate,bundle.ProbeCa,bundle.Root);
    try {
        using var tcp=new TcpClient(); tcp.Connect("127.0.0.1",server.Port);
        using var ssl=new SslStream(tcp.GetStream(),false,(_,cert,_,_)=> {
            using var chain=new X509Chain(); chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(bundle.Root); chain.ChainPolicy.ExtraStore.Add(bundle.ProbeCa); chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck; chain.ChainPolicy.DisableCertificateDownloads=true;
            return cert!=null && chain.Build((X509Certificate2)cert);
        });
        ssl.AuthenticateAsClient("test.ru"); ssl.Write(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: test.ru\r\n\r\n")); var bytes=new byte[4096]; var read=ssl.Read(bytes); Assert(System.Text.Encoding.ASCII.GetString(bytes,0,read).Contains("200 OK"),"Local HTTPS failed");
    } catch(Exception ex) { throw new Exception(ex.Message+" SERVER: "+server.LastFailure); } finally { server.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
});
Run("DNS, timeout and unknown authority are not constraint rejections", () => {
    Assert(BrowserProbe.ConstraintError("net::ERR_CERT_INVALID") && BrowserProbe.ConstraintError("net::ERR_CERT_NAME_CONSTRAINT_VIOLATION"),"Expected Chromium constraint codes");
    foreach(var error in new[]{"net::ERR_CERT_AUTHORITY_INVALID","net::ERR_NAME_NOT_RESOLVED","net::ERR_CONNECTION_TIMED_OUT","net::ERR_SSL_PROTOCOL_ERROR"}) Assert(!BrowserProbe.ConstraintError(error),"A network failure counted as protection");
});
Run("Reading physical Windows stores is stable and read only", () => {
    var stores=new WindowsTrustStores(); var a=stores.Read(); var b=stores.Read();
    string Digest(IReadOnlyList<TrustEntry> entries)=>string.Join(";",entries.Select(x=>$"{x.Store}/{x.Scope}/{Convert.ToHexString(x.Serialized)}").Order());
    Assert(Digest(a)==Digest(b),"Read changed serialized properties");
});
if(args.Contains("--browsers")) Run("Real Chrome/Edge do not accept an untrusted verification root", () => {
    using var bundle=CertificateFactory.Generate();
    foreach(var executable in BrowserProbe.InstalledBrowsers()) {
        Exception? failure=null; try { BrowserProbe.VerifyBrowser(executable,bundle).GetAwaiter().GetResult(); } catch(Exception ex) {failure=ex;}
        Assert(failure?.Message.Contains("net::ERR_CERT_AUTHORITY_INVALID")==true,$"Browser must reject unknown root: {Path.GetFileName(executable)} / {failure?.Message}");
        Console.WriteLine("  verified CDP and TLS in " + Path.GetFileName(executable));
    }
});
if(args.Contains("--browsers")) Run("Browser control is unavailable through local IPv4 and IPv6 TCP ports", () => BrowserSecurity.NoTcpControl().GetAwaiter().GetResult());
Run("Browser pipe preserves fragmented and coalesced UTF-8 messages", () => BrowserSecurity.Framing().GetAwaiter().GetResult());
Run("Browser launch does not inherit unrelated handles", () => BrowserSecurity.HandleIsolation().GetAwaiter().GetResult());
Run("Browser startup failure removes its temporary profile", () => BrowserSecurity.StartFailure().GetAwaiter().GetResult());
if(args.Contains("--browsers")) Run("Browser pipe navigation still receives a successful local HTTP response", () => BrowserSecurity.Navigation().GetAwaiter().GetResult());
using(var sources = SourceCatalog.Load()) {
    Run("Verify before installation reports a missing journal without changing trust", () => {
        foreach(var existingFolder in new[]{false,true}) WithService(2,TrustScope.User,(store,service,folder)=> {
            if(existingFolder) Directory.CreateDirectory(folder);
            var before=store.Digest(); Exception? failure=null;
            try {service.Verify();} catch(Exception ex) {failure=ex;}
            Assert(failure is InvalidOperationException && failure.Message=="Проверка недоступна: журнал установки не найден.","Expected a clear missing-journal message, got: " + failure?.Message);
            Assert(store.Operations==0 && store.Digest()==before,"Checking before installation changed trust");
            Assert(service.State=="None" && !File.Exists(Path.Combine(folder,"manifest.json")),"Checking before installation created an installation");
        });
    });
    foreach(var count in new[]{0,1,2}) Run($"Install/restore preserves baseline with {count} originals", () => {
        WithService(count,TrustScope.User,(store,service,folder)=> {
            var before=store.Digest(); service.Install(); service.Verify();
            Assert(store.Entries.Count==3,"Restricted root and two intermediates required");
            var installed=store.Digest(); var operations=store.Operations; service.Install(); Assert(store.Digest()==installed && store.Operations==operations,"Repeat install mutated stores");
            service.Restore(); Assert(store.Digest()==before,"Restore differs from baseline"); service.Restore(); Assert(store.Digest()==before,"Repeat restore differs");
        });
    });
    Run("Machine/policy roots block before any changes", () => {
        foreach(var scope in new[]{TrustScope.Machine,TrustScope.UserPolicy,TrustScope.MachinePolicy,TrustScope.Enterprise}) WithService(1,scope,(store,service,folder)=> {
            var before=store.Digest(); ExpectFailure(()=>service.Install()); Assert(store.Operations==0 && store.Digest()==before,"Unmanaged trust changed");
        });
    });
    Run("Equivalent RSA encodings are detected before installation and restored exactly", () => {
        foreach(var oid in new[]{"1.2.840.113549.1.1.1","1.2.840.113549.1.1.7","1.2.840.113549.1.1.10"}) {
            using var alternate=ReencodeRsaAlgorithm(sources.Certificates[0],oid);
            Assert(CertificateFactory.SameKey(sources.Certificates[0],alternate),"Equivalent RSA key was missed: " + oid);
            foreach(var scope in new[]{TrustScope.Machine,TrustScope.UserPolicy,TrustScope.MachinePolicy,TrustScope.Enterprise,TrustScope.User}) WithService(1,scope,(store,service,folder)=> {
                store.Entries[0]=new TrustEntry("Root",scope,alternate.RawData,alternate.Export(X509ContentType.SerializedCert)); var before=store.Digest();
                if(scope==TrustScope.User) {service.Install(); Assert(!store.Entries.Any(x=>x.Der.SequenceEqual(alternate.RawData)),"Alternate user root survived"); service.Restore(); Assert(store.Digest()==before,"Alternate root was not restored exactly");}
                else {ExpectFailure(()=>service.Install()); Assert(store.Operations==0 && store.Digest()==before,"Alternate unmanaged root was missed");}
            });
        }
        using var bundle=CertificateFactory.Generate(); Assert(!CertificateFactory.SameKey(sources.Certificates[0],bundle.Root),"Different RSA keys matched");
    });
    Run("Every store failure restores the full original state", () => {
        foreach(var fail in Enumerable.Range(1,5)) WithService(2,TrustScope.User,(store,service,folder)=> {
            var before=store.Digest(); store.FailAt=fail; ExpectFailure(()=>service.Install()); Assert(store.Digest()==before,$"Rollback at operation {fail} lost baseline");
        });
    });
    Run("Mandatory browser probe failure rolls back", () => WithService(2,TrustScope.User,(store,service,folder)=> {
        var before=store.Digest(); ExpectFailure(()=>service.Install(_=>throw new IOException("Browser rejects allowed domains"))); Assert(store.Digest()==before,"Probe failure did not roll back");
    }));
    Run("Interrupted apply is recovered by a new service", () => WithService(2,TrustScope.User,(store,service,folder)=> {
        var before=store.Digest(); service.Install();
        var statePath=Path.Combine(folder,"manifest.json"); var node=System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(statePath))!; node["Data"]!["State"]="Applying";
        var data=System.Text.Json.JsonSerializer.Deserialize<Installation>(node["Data"]!.ToJsonString())!;
        node["Hash"]=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(data))); File.WriteAllText(statePath,node.ToJsonString());
        new TrustService(store,folder,"test-user").Recover(); Assert(store.Digest()==before,"Interrupted install not restored");
    }));
    Run("Corrupt generated artifacts trigger rollback using intact backups", () => WithService(2,TrustScope.User,(store,service,folder)=> {
        var before=store.Digest(); service.Install(); File.WriteAllText(Path.Combine(folder,"root.cer"),"bad bytes"); ExpectFailure(()=>service.Verify()); Assert(store.Digest()==before,"Integrity failure did not restore");
    }));
    Run("Corrupt backups block recovery before deleting remaining trust", () => WithService(2,TrustScope.User,(store,service,folder)=> {
        service.Install(); var before=store.Digest(); var file=Directory.GetFiles(folder,"backup-*.serialized").First(); File.WriteAllText(file,"bad");
        var operations=store.Operations; ExpectFailure(()=>service.Restore()); Assert(store.Digest()==before && store.Operations==operations,"Corrupt recovery touched stores");
    }));
    Run("A different user cannot restore an installation", () => WithService(0,TrustScope.User,(store,service,folder)=> {
        service.Install(); var before=store.Digest(); ExpectFailure(()=>new TrustService(store,folder,"other-user").Restore()); Assert(store.Digest()==before,"Other user modified installation");
    }));
    Run("Missing, empty or partial baseline inventory cannot delete trust", () => {
        foreach(var mode in new[]{"missing","empty","partial"}) WithService(2,TrustScope.User,(store,service,folder)=> {
            service.Install(); var before=store.Digest(); var operations=store.Operations;
            var path=Path.Combine(folder,"manifest.json"); var node=System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path))!; var data=node["Data"] ?? node;
            if(mode=="missing") data.AsObject().Remove("Backups"); else if(mode=="empty") data["Backups"]=new System.Text.Json.Nodes.JsonArray(); else data["Backups"]!.AsArray().RemoveAt(0);
            File.WriteAllText(path,node.ToJsonString()); ExpectFailure(service.Restore); Assert(before==store.Digest() && operations==store.Operations,"Corrupt baseline silently lost original trust");
        });
    });
    Run("Prepared recovery never reinstalls externally removed originals", () => {
        foreach(var manual in new[]{false,true}) WithService(1,TrustScope.User,(store,service,folder)=> {
            store.OnRead=(s,n)=> {if(n==2) s.Entries.Clear();}; ExpectFailure(()=>service.Install()); Assert(store.Operations==0 && store.Entries.Count==0,"Preparation touched stores");
            var restarted=new TrustService(store,folder,"test-user"); if(manual) restarted.Restore(); else restarted.Recover(); Assert(store.Operations==0 && store.Entries.Count==0,"Prepared recovery reinstalled externally removed trust");
        });
    });
    void WithService(int count,TrustScope scope,Action<MemoryStores,TrustService,string> test) {
        var folder=Path.Combine(Path.GetTempPath(),"EbatVlastey-Test-"+Guid.NewGuid().ToString("N"));
        var store=new MemoryStores(); foreach(var cert in sources.Certificates.Take(count)) store.Entries.Add(new TrustEntry("Root",scope,cert.RawData,cert.Export(X509ContentType.SerializedCert)));
        try { test(store,new TrustService(store,folder,"test-user"),folder); } finally { if(Directory.Exists(folder)) Directory.Delete(folder,true); }
    }
}
return failures == 0 ? 0 : 1;
void ExpectFailure(Action action) { var failed=false; try {action();} catch(Exception ex) { Assert(ex is not NotImplementedException,"Feature is missing"); failed=true;} Assert(failed,"Expected failure was not detected"); }
void Run(string name, Action test) { try { test(); Console.WriteLine("PASS " + name); } catch(Exception ex) { failures++; Console.WriteLine("FAIL " + name + ": " + ex.Message); } }
void Assert(bool condition,string message) { if(!condition) throw new Exception(message); }
X509Certificate2 ReencodeRsaAlgorithm(X509Certificate2 source,string oid) {
    // A parsing fixture only: retain the old signature and change the SPKI algorithm.
    // It is never installed in Windows; trust-anchor detection must compare the key.
    var outer=new AsnReader(source.RawData,AsnEncodingRules.DER).ReadSequence();
    var tbs=new AsnReader(outer.ReadEncodedValue(),AsnEncodingRules.DER).ReadSequence();
    var fields=new List<byte[]>(); while(tbs.HasData) fields.Add(tbs.ReadEncodedValue().ToArray());
    var spki=new AsnReader(fields[6],AsnEncodingRules.DER).ReadSequence(); spki.ReadSequence(); var bits=spki.ReadBitString(out var unused);
    var replacement=new AsnWriter(AsnEncodingRules.DER); replacement.PushSequence(); replacement.PushSequence(); replacement.WriteObjectIdentifier(oid); replacement.PopSequence(); replacement.WriteBitString(bits,unused); replacement.PopSequence(); fields[6]=replacement.Encode();
    var writer=new AsnWriter(AsnEncodingRules.DER); writer.PushSequence(); writer.PushSequence(); foreach(var field in fields) writer.WriteEncodedValue(field); writer.PopSequence(); while(outer.HasData) writer.WriteEncodedValue(outer.ReadEncodedValue().Span); writer.PopSequence();
    return X509CertificateLoader.LoadCertificate(writer.Encode());
}
