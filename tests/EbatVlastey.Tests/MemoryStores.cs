using EbatVlastey.Core;
using System.Security.Cryptography.X509Certificates;
sealed class MemoryStores : ITrustStores {
    public List<TrustEntry> Entries {get;} = [];
    public int FailAt {get;set;} = -1;
    public int Operations {get;set;}
    public Action<MemoryStores,int>? OnRead {get;set;}
    int reads;
    public IReadOnlyList<TrustEntry> Read() { OnRead?.Invoke(this,++reads); return Entries.ToArray(); }
    public void Add(string store,byte[] bytes,bool requestApproval) {
        Tick(); using var cert = Decode(bytes);
        if(!Entries.Any(x=>x.Store==store && Thumb(x)==cert.Thumbprint && x.Scope==TrustScope.User)) Entries.Add(new TrustEntry(store,TrustScope.User,cert.RawData,bytes));
    }
    public void Remove(string store,string thumb) { Tick(); Entries.RemoveAll(x=>x.Store==store && x.Scope==TrustScope.User && Thumb(x)==thumb); }
    void Tick() { Operations++; if(Operations==FailAt) throw new IOException("Injected store failure"); }
    public string Digest() => string.Join(";", Entries.Select(x=>$"{x.Scope}/{x.Store}/{Thumb(x)}/{Convert.ToHexString(x.Serialized)}").Order());
    public void VerifyChains(CertificateBundle bundle,DateTimeOffset time) => ConstraintVerifier.Verify(bundle,time,false);
    static string Thumb(TrustEntry entry) { using var cert=Decode(entry.Der); return cert.Thumbprint; }
    static X509Certificate2 Decode(byte[] bytes) {
#pragma warning disable SYSLIB0057
        return new X509Certificate2(bytes);
#pragma warning restore SYSLIB0057
    }
}
