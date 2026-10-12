using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Net;
namespace EbatVlastey.Core;
public sealed record Probe(string Name, bool Expected, X509Certificate2 Certificate);
public sealed class CertificateBundle : IDisposable {
    public required X509Certificate2 Root { get; init; }
    public required X509Certificate2[] Crosses { get; init; }
    public required X509Certificate2 ProbeCa { get; init; }
    public required Probe[] Probes { get; init; }
    public void Dispose() { Root.Dispose(); ProbeCa.Dispose(); foreach(var c in Crosses) c.Dispose(); foreach(var p in Probes) p.Certificate.Dispose(); }
}
public sealed class SourceCatalog : IDisposable {
    public X509Certificate2[] Certificates {get;}
    private SourceCatalog(X509Certificate2[] certificates) => Certificates = certificates;
    public static SourceCatalog Load() {
        var specs = new[] {
            ("rsa", "8FF915CCAB7BC16F8C5C8099D53E0E115B3AEC2F", "D26D2D0231B7C39F92CC738512BA54103519E4405D68B5BD703E9788CA8ECF31"),
            ("gost", "656F78A4649A650E54043043B1C5EEEC128704A9", "5B51DB721B7C34958ED7432AE917A91297DD37508B2CAE4F858FFBAC6BC525EF")
        };
        var result = new List<X509Certificate2>();
        try {
            foreach(var (name, thumb, hash) in specs) {
                using var stream = typeof(SourceCatalog).Assembly.GetManifestResourceStream($"EbatVlastey.Core.Resources.{name}.cer") ?? throw new InvalidDataException("Нет исходного сертификата.");
                using var buffer = new MemoryStream(); stream.CopyTo(buffer); var bytes = buffer.ToArray();
                if(Convert.ToHexString(SHA256.HashData(bytes)) != hash) throw new InvalidDataException("Повреждён исходный сертификат.");
                var cert = X509CertificateLoader.LoadCertificate(bytes); result.Add(cert);
                if(cert.Thumbprint != thumb || cert.HasPrivateKey) throw new InvalidDataException("Неверный исходный сертификат.");
            }
            return new SourceCatalog(result.ToArray());
        } catch { foreach(var cert in result) cert.Dispose(); throw; }
    }
    public void Dispose() { foreach(var c in Certificates) c.Dispose(); }
}
public static class CertificateFactory {
    public static byte[] Constraints => Convert.FromHexString("304FA01B300582032E7275300582032E7375300B82092E786E2D2D70316169A130300A8708" + new string('0',16) + "30228720" + new string('0',64));
    public static bool SameKey(X509Certificate2 a,X509Certificate2 b) {
        if(!a.PublicKey.EncodedKeyValue.RawData.SequenceEqual(b.PublicKey.EncodedKeyValue.RawData)) return false;
        // All three RSA SPKI algorithms encode the same modulus and exponent.
        // NULL/absent parameters and OAEP/PSS restrictions do not change that key.
        static bool Rsa(string? oid) => oid is "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.7" or "1.2.840.113549.1.1.10";
        if(Rsa(a.PublicKey.Oid.Value) && Rsa(b.PublicKey.Oid.Value)) return true;
        return a.PublicKey.Oid.Value == b.PublicKey.Oid.Value && (a.PublicKey.EncodedParameters?.RawData ?? []).SequenceEqual(b.PublicKey.EncodedParameters?.RawData ?? []);
    }
    public static bool IsRestricted(X509Certificate2 cert) => cert.Extensions.Cast<X509Extension>().Any(x => x.Oid?.Value == "2.5.29.30" && x.Critical && x.RawData.SequenceEqual(Constraints));
    public static CertificateBundle Generate() {
        using var sources = SourceCatalog.Load();
        var now = DateTimeOffset.UtcNow;
        var end = new DateTimeOffset(sources.Certificates.Min(x => x.NotAfter).ToUniversalTime());
        if(end <= now.AddDays(2) || sources.Certificates.Any(x => x.NotBefore.ToUniversalTime() > now.UtcDateTime)) throw new InvalidOperationException("Исходные сертификаты ещё не действуют или скоро истекают.");
        using var rootKey = RSA.Create(4096);
        var request = new CertificateRequest($"CN=EbatVlastey Restricted RU Root {Guid.NewGuid():N}", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,true,5,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey,false)); AddConstraints(request);
        using var signedRoot = request.CreateSelfSigned(now.AddDays(-1),end);
        var root = X509CertificateLoader.LoadCertificate(signedRoot.RawData);
        var generator = X509SignatureGenerator.CreateForRSA(rootKey,RSASignaturePadding.Pkcs1);
        var crosses = new List<X509Certificate2>(); var probes = new List<Probe>(); X509Certificate2? probeCa = null;
        try {
            foreach(var source in sources.Certificates) crosses.Add(Cross(source,root,generator,now.AddHours(-1),end));
            using var caKey = RSA.Create(2048); using var leafKey = RSA.Create(2048);
            var caRequest = new CertificateRequest("CN=EbatVlastey Local Verification CA",caKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,true,1,true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign,true));
            caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey,false));
            using var caSource = caRequest.CreateSelfSigned(now.AddDays(-1),now.AddDays(2));
            probeCa = Cross(caSource,root,generator,now.AddHours(-1),now.AddDays(1));
            using var issuer = probeCa.CopyWithPrivateKey(caKey);
            foreach(var name in new[]{"test.ru","test.su","test.xn--p1ai","test.com","test.ru.example.com","mixed-ru-com","192.0.2.1","2001:db8::1","127.0.0.1","::1","signing-no-dns"}) {
                var leafRequest = new CertificateRequest("CN=EbatVlastey Verification Leaf",leafKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
                leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,true));
                leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new Oid("1.3.6.1.5.5.7.3.1")},false));
                var san = new SubjectAlternativeNameBuilder();
                if(IPAddress.TryParse(name,out var ip)) san.AddIpAddress(ip);
                else if(name == "mixed-ru-com") { san.AddDnsName("test.ru"); san.AddDnsName("test.com"); }
                else if(name != "signing-no-dns") san.AddDnsName(name);
                if(name != "signing-no-dns") leafRequest.CertificateExtensions.Add(san.Build());
                using var publicLeaf = leafRequest.Create(issuer,now.AddMinutes(-10),now.AddHours(12),RandomNumberGenerator.GetBytes(16));
                probes.Add(new Probe(name,name is "test.ru" or "test.su" or "test.xn--p1ai" or "signing-no-dns",publicLeaf.CopyWithPrivateKey(leafKey)));
            }
            return new CertificateBundle{Root=root,Crosses=crosses.ToArray(),ProbeCa=probeCa,Probes=probes.ToArray()};
        } catch { root.Dispose(); probeCa?.Dispose(); foreach(var c in crosses) c.Dispose(); foreach(var p in probes) p.Certificate.Dispose(); throw; }
    }
    private static void AddConstraints(CertificateRequest request) => request.CertificateExtensions.Add(new X509Extension("2.5.29.30",Constraints,true));
    private static X509Certificate2 Cross(X509Certificate2 source,X509Certificate2 root,X509SignatureGenerator generator,DateTimeOffset start,DateTimeOffset end) {
        var request = new CertificateRequest(source.SubjectName,source.PublicKey,HashAlgorithmName.SHA256);
        foreach(var extension in source.Extensions.Cast<X509Extension>().Where(x => x.Oid?.Value is not "2.5.29.35" and not "2.5.29.30")) request.CertificateExtensions.Add(new X509Extension(extension.Oid!,extension.RawData,extension.Critical));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root,true,false)); AddConstraints(request);
        return request.Create(root.SubjectName,generator,start,end,RandomNumberGenerator.GetBytes(16));
    }
}
