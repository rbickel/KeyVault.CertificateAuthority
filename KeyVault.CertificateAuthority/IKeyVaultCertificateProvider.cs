using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault;

namespace KeyVault.CertificateAuthority
{
    public interface IKeyVaultCertificateProvider
    {
        Task<KeyVaultCertificateWithPolicy> CreateCertificateWithDefaultsAsync(CertificateType certificateType, string issuerCertificateName, string certificateName, string subject, string[] san);
        Task<KeyVaultCertificateWithPolicy> CreateCertificateAsync(CertificateType certificateType, string issuerCertificateName, string certificateName, string subject, int durationInMonths, string[] san, int certPathLength);
        Task<KeyVaultCertificateWithPolicy> RenewCertificateAsync(KeyVaultCertificateWithPolicy certWithPolicy);
        Task<IList<X509Certificate2>> GetPublicCertificatesByName(IEnumerable<string> certNames);
        Task<X509Certificate2> GetCertificateAsync(string issuerCertificateName);

    }
}