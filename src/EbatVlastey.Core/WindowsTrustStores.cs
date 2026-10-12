using Microsoft.Win32;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
namespace EbatVlastey.Core;

public sealed class WindowsTrustStores : ITrustStores {
    const string SystemPath=@"Software\Microsoft\SystemCertificates\";
    public IReadOnlyList<TrustEntry> Read() {
        var entries=new List<TrustEntry>();
        foreach(var name in new[]{"Root","CA"}) {
            ReadPhysical(Registry.CurrentUser,SystemPath+name,name,TrustScope.User,entries);
            using(var machine=new X509Store(name,StoreLocation.LocalMachine)) { machine.Open(OpenFlags.ReadOnly); AddEntries(machine,name,TrustScope.Machine,entries); }
            ReadPhysical(Registry.CurrentUser,@"Software\Policies\Microsoft\SystemCertificates\"+name,name,TrustScope.UserPolicy,entries);
            ReadPhysical(Registry.LocalMachine,@"Software\Policies\Microsoft\SystemCertificates\"+name,name,TrustScope.MachinePolicy,entries);
            ReadPhysical(Registry.LocalMachine,@"Software\Microsoft\EnterpriseCertificates\"+name,name,TrustScope.Enterprise,entries);
            using var logical=new X509Store(name,StoreLocation.CurrentUser); logical.Open(OpenFlags.ReadOnly);
            foreach(var cert in logical.Certificates) { using(cert) { if(!entries.Any(x=>x.Store==name && x.Der.SequenceEqual(cert.RawData))) entries.Add(new TrustEntry(name,TrustScope.Enterprise,cert.RawData,cert.Export(X509ContentType.SerializedCert))); } }
        }
        return entries;
    }
    static void AddEntries(X509Store store,string name,TrustScope scope,List<TrustEntry> result) {
        foreach(var cert in store.Certificates) using(cert) result.Add(new TrustEntry(name,scope,cert.RawData,cert.Export(X509ContentType.SerializedCert)));
    }
    static void ReadPhysical(RegistryKey hive,string path,string name,TrustScope scope,List<TrustEntry> result) {
        using var key=hive.OpenSubKey(path,false); if(key==null) return; using var store=OpenRegistry(key,true); AddEntries(store,name,scope,result);
    }
    public void Add(string storeName,byte[] bytes,bool requestApproval) {
        GuardStore(storeName); using var cert=Load(bytes); if(cert.HasPrivateKey) throw new InvalidDataException("Секретные ключи в хранилища не устанавливаются.");
        if(storeName=="Root" && requestApproval) {
            // Standard Windows consent is required for a new trusted root.
            using var standard=new X509Store("Root",StoreLocation.CurrentUser); standard.Open(OpenFlags.ReadWrite); standard.Add(cert);
        } else {
            // REG provider changes only this user's physical store and preserves
            // previously approved root identities for reliable recovery.
            using var key=Registry.CurrentUser.CreateSubKey(SystemPath+storeName,true); using var store=OpenRegistry(key,false);
            if(!store.Certificates.Cast<X509Certificate2>().Any(c=>c.Thumbprint==cert.Thumbprint)) store.Add(cert);
        }
        using var visible=new X509Store(storeName,StoreLocation.CurrentUser); visible.Open(OpenFlags.ReadOnly);
        if(!visible.Certificates.Cast<X509Certificate2>().Any(c=>c.Thumbprint==cert.Thumbprint)) throw new InvalidOperationException("Windows не подтвердил установку сертификата.");
    }
    public void Remove(string storeName,string thumbprint) {
        GuardStore(storeName); using var key=Registry.CurrentUser.OpenSubKey(SystemPath+storeName,true); if(key==null) return;
        using var store=OpenRegistry(key,false); foreach(var cert in store.Certificates) using(cert) { if(cert.Thumbprint==thumbprint) store.Remove(cert); }
    }
    public void VerifyChains(CertificateBundle bundle,DateTimeOffset time) => ConstraintVerifier.Verify(bundle,time,true);
    static void GuardStore(string name) { if(name is not ("Root" or "CA")) throw new ArgumentException("Недопустимое хранилище."); }
    static X509Certificate2 Load(byte[] bytes) {
#pragma warning disable SYSLIB0057
        return new X509Certificate2(bytes);
#pragma warning restore SYSLIB0057
    }
    static X509Store OpenRegistry(RegistryKey key,bool readOnly) {
        var handle=CertOpenStore(new IntPtr(4),0,IntPtr.Zero,readOnly?0x8000u:0u,key.Handle.DangerousGetHandle());
        if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return new X509Store(handle); } finally { CertCloseStore(handle,0); }
    }
    [DllImport("crypt32.dll",SetLastError=true)] static extern IntPtr CertOpenStore(IntPtr provider,uint encoding,IntPtr crypto,uint flags,IntPtr parameter);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CertCloseStore(IntPtr store,uint flags);
}
