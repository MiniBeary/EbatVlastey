using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
namespace EbatVlastey.Core;

public sealed record Artifact(string File, string Hash, string Thumbprint);
public sealed record Backup(Artifact Der, Artifact Serialized);
public sealed class Installation {
    public int Schema {get;set;} = 1;
    public string UserId {get;set;} = "";
    public string State {get;set;} = "Prepared";
    public DateTimeOffset Created {get;set;}
    public Artifact Root {get;set;} = new("","","");
    public List<Artifact> Crosses {get;set;} = [];
    public Artifact ProbeCa {get;set;} = new("","","");
    public List<Artifact> Probes {get;set;} = [];
    public List<Backup> Backups {get;set;} = [];
    public string? LastError {get;set;}
}
public sealed record Journal(Installation Data,string Hash);

public sealed class TrustService(ITrustStores stores,string directory,string userId) {
    static readonly JsonSerializerOptions JsonOptions = new(){WriteIndented=true};
    readonly string directory = Path.GetFullPath(directory);
    public string State => File.Exists(Path.Combine(directory,"manifest.json")) ? Read().State : "None";
    public void Install(Func<CertificateBundle,Task>? browserProbe = null) => Locked(() => {
        RecoverInternal();
        if(State == "Applied") { VerifyInternal(); return; }
        var entries = Preflight();
        ArchivePrevious();
        Directory.CreateDirectory(directory);
        using var bundle = CertificateFactory.Generate();
        ConstraintVerifier.Verify(bundle,DateTimeOffset.UtcNow,false);
        var m = new Installation{UserId=userId,Created=DateTimeOffset.UtcNow};
        m.Root = WriteCert("root.cer",bundle.Root.RawData);
        for(var i=0;i<bundle.Crosses.Length;i++) m.Crosses.Add(WriteCert($"cross-{i}.cer",bundle.Crosses[i].RawData));
        m.ProbeCa = WriteCert("probe-ca.cer",bundle.ProbeCa.RawData);
        for(var i=0;i<bundle.Probes.Length;i++) m.Probes.Add(WriteCert($"probe-{i}.cer",bundle.Probes[i].Certificate.RawData));
        foreach(var entry in entries) {
            using var cert = Load(entry.Der);
            m.Backups.Add(new Backup(WriteCert($"backup-{cert.Thumbprint}.cer",entry.Der),WriteCert($"backup-{cert.Thumbprint}.serialized",entry.Serialized)));
        }
        Save(m); ValidateBackups(m); using var validated = LoadBundle(m);
        var current = Preflight();
        if(Digest(entries) != Digest(current)) throw new InvalidOperationException("Хранилище изменилось во время подготовки. Повторите установку.");
        m.State = "Applying"; Save(m);
        try {
            stores.Add("Root",bundle.Root.RawData,true);
            foreach(var cert in bundle.Crosses) stores.Add("CA",cert.RawData,false);
            foreach(var backup in m.Backups) stores.Remove("Root",backup.Der.Thumbprint);
            CheckInstalled(m); stores.VerifyChains(bundle,m.Created);
            browserProbe?.Invoke(bundle).GetAwaiter().GetResult();
            m.State = "Applied"; Save(m);
        } catch(Exception failure) {
            m.LastError = failure.Message;
            try { RestoreInternal(m); } catch(Exception recovery) { throw new AggregateException("Установка не завершена; автоматическое восстановление не завершено. Сохраните резервную копию и повторите «Восстановить».",failure,recovery); }
            throw new InvalidOperationException("Установка отменена. Прежнее состояние восстановлено. " + failure.Message,failure);
        }
    });
    public void Verify() => Locked(() => { RecoverInternal(); VerifyInternal(); });
    public void Restore() => Locked(() => { if(State is "None" or "RolledBack") return; if(State=="Prepared") {RecoverInternal();return;} RestoreInternal(Read()); });
    public void Recover() => Locked(RecoverInternal);
    void RecoverInternal() {
        if(State=="Prepared") {var m=Read(); m.State="RolledBack"; Save(m); return;}
        if(State is "Applying" or "RollingBack") RestoreInternal(Read());
    }
    void VerifyInternal() {
        var m = Read(); if(m.State != "Applied") throw new InvalidOperationException("Ограничение этой программой не установлено.");
        try { ValidateBackups(m); using var bundle=LoadBundle(m); CheckInstalled(m); stores.VerifyChains(bundle,m.Created); }
        catch(Exception failure) {
            m.LastError = failure.Message;
            try { RestoreInternal(m); } catch(Exception recovery) { throw new AggregateException("Проверка обнаружила сбой; восстановление не завершено. Не удаляйте резервную копию.",failure,recovery); }
            throw new InvalidOperationException("Проверка не пройдена. Прежнее состояние восстановлено. " + failure.Message,failure);
        }
    }
    IReadOnlyList<TrustEntry> Preflight() {
        using var sources=SourceCatalog.Load();
        var roots=stores.Read().Where(x=>x.Store=="Root").Where(x=> { using var c=Load(x.Der); return sources.Certificates.Any(s=>CertificateFactory.SameKey(s,c)); }).ToArray();
        if(roots.Any(x=>x.Scope!=TrustScope.User)) throw new InvalidOperationException("Исходные сертификаты найдены на уровне компьютера или корпоративной политики. Настройка одного пользователя не устранит это доверие; изменения не выполнены.");
        foreach(var entry in roots) { using var c=Load(entry.Serialized); if(c.HasPrivateKey) throw new InvalidOperationException("Неожиданный секретный ключ у исходного сертификата."); }
        return roots;
    }
    void RestoreInternal(Installation m) {
        ValidateBackups(m);
        var entries=stores.Read();
        // Check installed records against the journal even when a disk artifact is damaged.
        foreach(var (store,artifact) in Owned(m)) foreach(var entry in entries.Where(x=>x.Scope==TrustScope.User && x.Store==store)) {
            using var cert=Load(entry.Der);
            if(cert.Thumbprint==artifact.Thumbprint && Hash(entry.Der)!=artifact.Hash) throw new InvalidDataException("Запись хранилища не совпадает с журналом восстановления.");
        }
        m.State="RollingBack"; Save(m);
        foreach(var backup in m.Backups) stores.Add("Root",ReadArtifact(backup.Serialized),false);
        foreach(var artifact in m.Crosses) stores.Remove("CA",artifact.Thumbprint);
        stores.Remove("Root",m.Root.Thumbprint);
        entries=stores.Read();
        foreach(var backup in m.Backups) if(!entries.Any(x=>x.Scope==TrustScope.User && x.Store=="Root" && Hash(x.Der)==backup.Der.Hash && Hash(x.Serialized)==backup.Serialized.Hash)) throw new InvalidOperationException("Исходный сертификат не восстановлен полностью.");
        foreach(var (store,artifact) in Owned(m)) if(entries.Any(x=>x.Scope==TrustScope.User && x.Store==store && Hash(x.Der)==artifact.Hash)) throw new InvalidOperationException("Созданный сертификат остался после восстановления.");
        m.State="RolledBack"; Save(m);
    }
    void CheckInstalled(Installation m) {
        var entries=stores.Read(); using var sources=SourceCatalog.Load();
        foreach(var (store,artifact) in Owned(m)) if(!entries.Any(x=>x.Scope==TrustScope.User && x.Store==store && Hash(x.Der)==artifact.Hash)) throw new InvalidOperationException("Не найден установленный сертификат: " + artifact.File);
        foreach(var entry in entries.Where(x=>x.Store=="Root")) {
            using var cert=Load(entry.Der);
            if(sources.Certificates.Any(s=>CertificateFactory.SameKey(s,cert)) || m.Crosses.Any(c=>c.Thumbprint==cert.Thumbprint)) throw new InvalidOperationException("Обнаружен другой путь доверия к Минцифры через корневое хранилище.");
        }
        using var root=Load(ReadArtifact(m.Root));
        if(root.NotBefore.ToUniversalTime()>DateTime.UtcNow || root.NotAfter.ToUniversalTime()<=DateTime.UtcNow) throw new InvalidOperationException("Срок действия ограничения истёк или ещё не начался.");
    }
    void ValidateBackups(Installation m) {
        using var sources=SourceCatalog.Load();
        foreach(var backup in m.Backups) {
            using var der=Load(ReadArtifact(backup.Der)); using var serialized=Load(ReadArtifact(backup.Serialized));
            if(der.HasPrivateKey || serialized.HasPrivateKey || !der.RawData.SequenceEqual(serialized.RawData) || !sources.Certificates.Any(s=>CertificateFactory.SameKey(s,der))) throw new InvalidDataException("Неверная резервная копия исходного сертификата.");
        }
    }
    CertificateBundle LoadBundle(Installation m) {
        using var sources=SourceCatalog.Load();
        var certificates=new List<X509Certificate2>();
        X509Certificate2 ReadCert(Artifact a) { var c=Load(ReadArtifact(a)); certificates.Add(c); return c; }
        try {
            var root=ReadCert(m.Root); var crosses=m.Crosses.Select(ReadCert).ToArray(); var ca=ReadCert(m.ProbeCa);
            if(root.HasPrivateKey || !CertificateFactory.IsRestricted(root) || crosses.Length!=2) throw new InvalidDataException("Неверный ограниченный корень.");
            for(var i=0;i<2;i++) {
                var c=crosses[i]; var source=sources.Certificates[i];
                if(c.HasPrivateKey || !CertificateFactory.IsRestricted(c) || !CertificateFactory.SameKey(c,source) || !c.SubjectName.RawData.SequenceEqual(source.SubjectName.RawData) || c.NotAfter>source.NotAfter || c.NotAfter>root.NotAfter) throw new InvalidDataException("Неверная ограниченная версия сертификата.");
                using var chain=new X509Chain(); chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(root); chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck; chain.ChainPolicy.DisableCertificateDownloads=true; chain.ChainPolicy.VerificationTime=m.Created.LocalDateTime;
                if(!chain.Build(c)) throw new InvalidDataException("Повреждена подпись ограниченной версии.");
            }
            var names=ConstraintVerifier.Names;
            if(m.Probes.Count!=names.Length) throw new InvalidDataException("Отсутствуют обязательные тесты.");
            return new CertificateBundle{Root=root,Crosses=crosses,ProbeCa=ca,Probes=m.Probes.Select((a,i)=>new Probe(names[i],ConstraintVerifier.Allowed.Contains(names[i]),ReadCert(a))).ToArray()};
        } catch { foreach(var c in certificates) c.Dispose(); throw; }
    }
    Installation Read() {
        var journal=JsonSerializer.Deserialize<Journal>(File.ReadAllBytes(Path.Combine(directory,"manifest.json"))) ?? throw new InvalidDataException("Повреждён журнал установки.");
        var m=journal.Data;
        if(m==null || journal.Hash!=Hash(JsonSerializer.SerializeToUtf8Bytes(m))) throw new InvalidDataException("Нарушена целостность журнала установки. Хранилища не изменены; сохраните резервную копию.");
        if(m.Schema!=1 || m.UserId!=userId || m.State is not ("Prepared" or "Applying" or "Applied" or "RollingBack" or "RolledBack")) throw new InvalidDataException("Журнал имеет неизвестный формат или принадлежит другому пользователю.");
        return m;
    }
    Artifact WriteCert(string name,byte[] bytes) { AtomicWrite(LocalPath(name),bytes); using var cert=Load(bytes); if(cert.HasPrivateKey) throw new InvalidDataException("Сохранение секретного ключа запрещено."); return new Artifact(name,Hash(bytes),cert.Thumbprint); }
    byte[] ReadArtifact(Artifact artifact) {
        var bytes=File.ReadAllBytes(LocalPath(artifact.File)); if(Hash(bytes)!=artifact.Hash) throw new InvalidDataException("Повреждён файл: " + artifact.File);
        using var cert=Load(bytes); if(cert.Thumbprint!=artifact.Thumbprint || cert.HasPrivateKey) throw new InvalidDataException("Неверный сертификат: " + artifact.File); return bytes;
    }
    string LocalPath(string name) { if(string.IsNullOrWhiteSpace(name) || Path.GetFileName(name)!=name || name.Contains(':')) throw new InvalidDataException("Неверный путь в журнале."); return Path.Combine(directory,name); }
    void Save(Installation m) => AtomicWrite(Path.Combine(directory,"manifest.json"),JsonSerializer.SerializeToUtf8Bytes(new Journal(m,Hash(JsonSerializer.SerializeToUtf8Bytes(m))),JsonOptions));
    static void AtomicWrite(string path,byte[] bytes) {
        var temp=path+".tmp"; using(var stream=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)) { stream.Write(bytes); stream.Flush(true); } File.Move(temp,path,true);
    }
    void ArchivePrevious() { if(!Directory.Exists(directory) || !File.Exists(Path.Combine(directory,"manifest.json"))) return; var target=Path.Combine(directory,"history",DateTime.UtcNow.ToString("yyyyMMddTHHmmss")+"-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(target); foreach(var file in Directory.GetFiles(directory).Where(f=>Path.GetFileName(f)!="operation.lock")) File.Move(file,Path.Combine(target,Path.GetFileName(file))); }
    static IEnumerable<(string Store,Artifact Artifact)> Owned(Installation m) { yield return ("Root",m.Root); foreach(var c in m.Crosses) yield return ("CA",c); }
    static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    static string Digest(IEnumerable<TrustEntry> entries) => string.Join(";",entries.Select(x=>Hash(x.Serialized)).Order());
    static X509Certificate2 Load(byte[] bytes) {
#pragma warning disable SYSLIB0057 // SerializedCert includes public context properties, not a PFX.
        return new X509Certificate2(bytes);
#pragma warning restore SYSLIB0057
    }
    void Locked(Action action) {
        var name="Local\\EbatVlastey-"+Hash(System.Text.Encoding.UTF8.GetBytes(userId)); using var mutex=new Mutex(false,name); var acquired=false;
        try {
            try { acquired=mutex.WaitOne(0); } catch(AbandonedMutexException) { acquired=true; }
            if(!acquired) throw new InvalidOperationException("Другая операция уже выполняется.");
            Directory.CreateDirectory(directory);
            FileStream lease;
            try {lease=new FileStream(Path.Combine(directory,"operation.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);}
            catch(IOException ex) {throw new InvalidOperationException("Другая операция использует папку установки; либо папка недоступна.",ex);}
            using(lease) action();
        } finally { if(acquired) mutex.ReleaseMutex(); }
    }
}

public static class ConstraintVerifier {
    public static readonly string[] Names=["test.ru","test.su","test.xn--p1ai","test.com","test.ru.example.com","mixed-ru-com","192.0.2.1","2001:db8::1","127.0.0.1","::1","signing-no-dns"];
    public static readonly string[] Allowed=["test.ru","test.su","test.xn--p1ai","signing-no-dns"];
    public static void Verify(CertificateBundle bundle,DateTimeOffset time,bool systemTrust) {
        foreach(var p in bundle.Probes) {
            using var chain=new X509Chain(); chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck; chain.ChainPolicy.DisableCertificateDownloads=true; chain.ChainPolicy.VerificationTime=time.LocalDateTime;
            chain.ChainPolicy.ExtraStore.Add(bundle.ProbeCa);
            if(!systemTrust) { chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(bundle.Root); }
            var accepted=chain.Build(p.Certificate);
            if(accepted!=Allowed.Contains(p.Name) || (!accepted && !chain.ChainStatus.Any(s=>s.Status.ToString().Contains("NameConstraint"))) || !chain.ChainElements.Cast<X509ChainElement>().Any(e=>e.Certificate.Thumbprint==bundle.Root.Thumbprint)) throw new InvalidOperationException("Проверка ограничений Windows не пройдена: " + p.Name);
        }
    }
}
