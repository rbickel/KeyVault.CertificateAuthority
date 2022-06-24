using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;

namespace KeyVault.CertificateAuthority
{
    public interface IKeyVaultCertificateProvider
    {
        Task CreateCertificateAsync(string issuerCertificateName, string certificateName, string subject, int durationDays, string[] san, int certPathLength = 1);
        Task RenewCertificateAsync(KeyVaultCertificateWithPolicy certWithPolicy, int duration);

        Task<IList<X509Certificate2>> GetPublicCertificatesByName(IEnumerable<string> certNames);

        Task<X509Certificate2> GetCertificateAsync(string issuerCertificateName);

    }
}