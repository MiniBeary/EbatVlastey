namespace EbatVlastey.Core;
public enum TrustScope { User, Machine, UserPolicy, MachinePolicy, Enterprise }
public sealed record TrustEntry(string Store, TrustScope Scope, byte[] Der, byte[] Serialized);
public interface ITrustStores {
    IReadOnlyList<TrustEntry> Read();
    void Add(string store, byte[] certificate, bool requestApproval);
    void Remove(string store, string thumbprint);
    void VerifyChains(CertificateBundle bundle, DateTimeOffset time);
}
