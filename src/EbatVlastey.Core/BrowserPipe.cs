using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

namespace EbatVlastey.Core;

// Chromium's Windows pipe transport consumes two explicitly inherited handles.
// No named endpoint or TCP listener is created for browser control.
sealed class BrowserPipe : IAsyncDisposable {
    readonly AnonymousPipeServerStream outgoing;
    readonly AnonymousPipeServerStream incoming;
    readonly Channel<JsonElement> messages=Channel.CreateBounded<JsonElement>(new BoundedChannelOptions(256){SingleReader=true,SingleWriter=true});
    readonly CancellationTokenSource stop=new();
    Task? reader;
    internal BrowserPipe() {
        outgoing=new(PipeDirection.Out,HandleInheritability.Inheritable);
        try { incoming=new(PipeDirection.In,HandleInheritability.Inheritable); }
        catch { outgoing.Dispose(); stop.Dispose(); throw; }
    }
    internal SafePipeHandle ChildInput=>outgoing.ClientSafePipeHandle;
    internal SafePipeHandle ChildOutput=>incoming.ClientSafePipeHandle;
    internal string ChildHandles=>HandleValue(ChildInput)+","+HandleValue(ChildOutput);
    static string HandleValue(SafePipeHandle handle)=>unchecked((uint)handle.DangerousGetHandle().ToInt64()).ToString(CultureInfo.InvariantCulture);
    internal void StartReading() {
        outgoing.DisposeLocalCopyOfClientHandle(); incoming.DisposeLocalCopyOfClientHandle();
        reader=Task.Run(ReadMessages);
    }
    void ReadMessages() {
        try {
            using var frame=new MemoryStream(); var buffer=new byte[8192];
            while(true) {
                var count=incoming.Read(buffer,0,buffer.Length);
                if(count==0) throw new IOException("Соединение с браузером закрыто.");
                for(var i=0;i<count;i++) {
                    if(buffer[i]!=0) {
                        if(frame.Length>=2_000_000) throw new IOException("Слишком большой ответ браузера.");
                        frame.WriteByte(buffer[i]); continue;
                    }
                    using var json=JsonDocument.Parse(frame.GetBuffer().AsMemory(0,checked((int)frame.Length)));
                    messages.Writer.WriteAsync(json.RootElement.Clone(),stop.Token).AsTask().GetAwaiter().GetResult();
                    frame.SetLength(0);
                }
            }
        } catch(Exception ex) when(ex is IOException or JsonException or OperationCanceledException or ObjectDisposedException) { messages.Writer.TryComplete(ex); }
    }
    internal async Task Send(byte[] message,CancellationToken token) {
        var frame=new byte[message.Length+1]; message.CopyTo(frame,0);
        await outgoing.WriteAsync(frame,token).AsTask().WaitAsync(token);
    }
    internal async Task<JsonElement> Receive(CancellationToken token) {
        try { return await messages.Reader.ReadAsync(token); }
        catch(ChannelClosedException ex) { throw new IOException("Соединение с браузером закрыто.",ex.InnerException); }
    }
    public async ValueTask DisposeAsync() {
        stop.Cancel(); outgoing.Dispose(); incoming.Dispose();
        if(reader!=null) await reader;
        stop.Dispose();
    }
}

static class BrowserPipeProcess {
    internal static Process Start(string executable,IReadOnlyList<string> arguments,SafePipeHandle input,SafePipeHandle output) {
        // Restrict inheritance to these two child ends, even if another thread
        // has opened an inheritable handle elsewhere in the application.
        nuint size=0; InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
        if(size==0) throw new Win32Exception(Marshal.GetLastWin32Error());
        var attributes=Marshal.AllocHGlobal(checked((nint)size));
        var handles=Marshal.AllocHGlobal(2*IntPtr.Size); var initialized=false;
        try {
            if(!InitializeProcThreadAttributeList(attributes,1,0,ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            initialized=true;
            Marshal.WriteIntPtr(handles,0,input.DangerousGetHandle()); Marshal.WriteIntPtr(handles,IntPtr.Size,output.DangerousGetHandle());
            if(!UpdateProcThreadAttribute(attributes,0,0x00020002,handles,(nuint)(2*IntPtr.Size),IntPtr.Zero,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var startup=new StartupInfoEx {StartupInfo=new StartupInfo{Size=Marshal.SizeOf<StartupInfoEx>()},Attributes=attributes};
            var command=new StringBuilder(string.Join(" ",new[]{executable}.Concat(arguments).Select(Quote)));
            if(!CreateProcess(executable,command,IntPtr.Zero,IntPtr.Zero,true,0x00080000|0x08000000,IntPtr.Zero,null,ref startup,out var info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { return Process.GetProcessById(checked((int)info.ProcessId)); }
            finally { CloseHandle(info.Thread); CloseHandle(info.Process); }
        } finally {
            if(initialized) DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(handles); Marshal.FreeHGlobal(attributes);
        }
    }
    internal static string Quote(string value) {
        var quoted=new StringBuilder("\""); var slashes=0;
        foreach(var c in value) {
            if(c=='\\') {slashes++; continue;}
            quoted.Append('\\',c=='"'?2*slashes+1:slashes).Append(c); slashes=0;
        }
        return quoted.Append('\\',2*slashes).Append('"').ToString();
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
        internal int Size;
        internal IntPtr Reserved,Desktop,Title;
        internal uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;
        internal ushort ShowWindow,ReservedSize;
        internal IntPtr ReservedBytes,Input,Output,Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupInfoEx {internal StartupInfo StartupInfo;internal IntPtr Attributes;}
    [StructLayout(LayoutKind.Sequential)] struct ProcessInformation {internal IntPtr Process,Thread;internal uint ProcessId,ThreadId;}
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool InitializeProcThreadAttributeList(IntPtr list,uint count,uint flags,ref nuint size);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,nuint attribute,IntPtr value,nuint size,IntPtr previous,IntPtr returnedSize);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll",EntryPoint="CreateProcessW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CreateProcess(string executable,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,[MarshalAs(UnmanagedType.Bool)] bool inherit,uint flags,IntPtr environment,string? directory,ref StartupInfoEx startup,out ProcessInformation information);
    [DllImport("kernel32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CloseHandle(IntPtr handle);
}
