using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Win32.SafeHandles;
using EbatVlastey.Core;

static class BrowserSecurity {
    public static async Task NoTcpControl() {
        foreach(var executable in BrowserProbe.InstalledBrowsers()) {
            await using var browser=await CdpBrowser.Start(executable);
            var process=(Process)typeof(CdpBrowser).GetField("process",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(browser)!;
            var profile=(string)typeof(CdpBrowser).GetField("profile",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(browser)!;
            if(File.Exists(Path.Combine(profile,"DevToolsActivePort"))) throw new Exception("TCP discovery file was created");
            foreach(var family in new[]{2u,23u}) {
                var ports=ListeningPorts(process.Id,family);
                if(ports.Length!=0) throw new Exception($"{Path.GetFileName(executable)} exposes a TCP listener: {string.Join(",",ports)}");
            }
            Console.WriteLine("  no TCP control in " + Path.GetFileName(executable));
        }
    }
    public static async Task Framing() {
        await using var pipe=new BrowserPipe();
        if(!DuplicateHandle(new IntPtr(-1),pipe.ChildOutput,new IntPtr(-1),out var duplicate,0,false,2)) throw new IOException("DuplicateHandle failed");
        using var writer=new AnonymousPipeClientStream(PipeDirection.Out,duplicate);
        pipe.StartReading();
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var bytes=Encoding.UTF8.GetBytes("{\"id\":1,\"text\":\"проверка\"}\0{\"id\":2}\0");
        // Split a UTF-8 code point and put both frame boundaries in the next write.
        var split=Array.FindIndex(bytes,b=>b>=128)+1;
        await writer.WriteAsync(bytes.AsMemory(0,split),timeout.Token);
        await writer.WriteAsync(bytes.AsMemory(split),timeout.Token);
        var first=await pipe.Receive(timeout.Token); var second=await pipe.Receive(timeout.Token);
        if(first.GetProperty("text").GetString()!="проверка" || second.GetProperty("id").GetInt32()!=2) throw new Exception("Pipe corrupted message framing");
        writer.Dispose();
        try { await pipe.Receive(timeout.Token); throw new Exception("EOF was accepted as a CDP message"); } catch(IOException) { }
    }
    public static async Task HandleIsolation() {
        var security=new SecurityAttributes{Size=Marshal.SizeOf<SecurityAttributes>(),Inherit=true};
        using var unrelated=CreateEvent(ref security,false,false,null);
        if(unrelated.IsInvalid) throw new IOException("CreateEvent failed");
        await using var pipe=new BrowserPipe();
        var executable=Environment.ProcessPath ?? throw new IOException("Test executable not found");
        using var child=BrowserPipeProcess.Start(executable,["--inheritance-child",unrelated.DangerousGetHandle().ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture)],pipe.ChildInput,pipe.ChildOutput);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await child.WaitForExitAsync(timeout.Token);
        if(child.ExitCode!=0 || WaitForSingleObject(unrelated,0)!=258) throw new Exception("Unrelated inheritable event reached the child process");
    }
    public static int CheckInheritedHandle(string value)=>SetEvent(new IntPtr(long.Parse(value,System.Globalization.CultureInfo.InvariantCulture)))?88:0;
    public static async Task StartFailure() {
        var before=Directory.GetDirectories(Path.GetTempPath(),"EbatVlastey-Browser-*").ToHashSet(StringComparer.OrdinalIgnoreCase);
        try { await using var browser=await CdpBrowser.Start(Path.Combine(Path.GetTempPath(),"missing browser "+Guid.NewGuid().ToString("N"),"chrome.exe")); throw new Exception("Missing browser started"); }
        catch(System.ComponentModel.Win32Exception) { }
        if(Directory.GetDirectories(Path.GetTempPath(),"EbatVlastey-Browser-*").Any(p=>!before.Contains(p))) throw new Exception("Failed launch left a temporary profile");
    }
    public static async Task Navigation() {
        foreach(var executable in BrowserProbe.InstalledBrowsers()) {
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
            var serve=Task.Run(async()=> {
                using var client=await listener.AcceptTcpClientAsync(timeout.Token); using var stream=client.GetStream();
                var buffer=new byte[4096]; if(await stream.ReadAsync(buffer,timeout.Token)==0) throw new IOException("No HTTP request received");
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"),timeout.Token);
            });
            await using var browser=await CdpBrowser.Start(executable);
            var result=await browser.Navigate($"http://test.ru:{((IPEndPoint)listener.LocalEndpoint).Port}/probe");
            await serve;
            if(result!="OK") throw new Exception("Successful local navigation failed: " + result);
            Console.WriteLine("  successful pipe navigation in " + Path.GetFileName(executable));
        }
    }
    static int[] ListeningPorts(int pid,uint family) {
        uint size=0; GetExtendedTcpTable(IntPtr.Zero,ref size,false,family,3,0);
        var buffer=Marshal.AllocHGlobal(checked((int)size));
        try {
            var result=GetExtendedTcpTable(buffer,ref size,false,family,3,0);
            if(result!=0) throw new IOException("TCP table read failed: " + result);
            var count=Marshal.ReadInt32(buffer); var ports=new List<int>();
            var stride=family==2?24:56; var ownerOffset=family==2?20:52; var portOffset=family==2?8:20;
            for(var i=0;i<count;i++) {
                var row=IntPtr.Add(buffer,4+i*stride);
                if(Marshal.ReadInt32(row,ownerOffset)!=pid) continue;
                var port=Marshal.ReadInt32(row,portOffset);
                ports.Add(((port&255)<<8)|((port>>8)&255));
            }
            return ports.ToArray();
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table,ref uint size,[MarshalAs(UnmanagedType.Bool)] bool order,uint family,uint tableClass,uint reserved);
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {internal int Size;internal IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)] internal bool Inherit;}
    [DllImport("kernel32.dll",EntryPoint="CreateEventW",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeWaitHandle CreateEvent(ref SecurityAttributes security,[MarshalAs(UnmanagedType.Bool)] bool manual,[MarshalAs(UnmanagedType.Bool)] bool initial,string? name);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(SafeWaitHandle handle,uint timeout);
    [DllImport("kernel32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool DuplicateHandle(IntPtr sourceProcess,SafePipeHandle source,IntPtr targetProcess,out SafePipeHandle target,uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint options);
}
