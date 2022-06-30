using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Identity;
using KeyVault.CertificateAuthority;

namespace KeyVault.CertificateTests;

public class CACertificateTests
{
    private KeyVaultCertificateProvider _kvCertProvider;

    public CACertificateTests()
    {
        var _keyVaultUrl = Config.Instance.KeyVaultUri;
        _kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(_keyVaultUrl);
    }

    [Fact(DisplayName = "CA should not have an exportable key")]
    public async Task CACertificates_KeysExportable_ReturnFalse()
    {
        var result = await _kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "test-ca", "test-ca", "CN=test-ca", new string[] { });

        Assert.False(result.Policy.Exportable);
    }

    [Fact(DisplayName = "CA should reuse keys")]
    public async Task CACertificates_ReuseKeys_ReturnTrue()
    {
        var result = await _kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "test-ca2", "test-ca2", "CN=test-ca2", new string[] { });

        Assert.True(result.Policy.ReuseKey);
    }

    [Fact(DisplayName = "Renewed CA certificate must have same private keys")]
    public async Task CACertificates_RenewSameKey_ReturnTrue()
    {
        var initialCert = await _kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "test-ca3", "test-ca3", "CN=test-ca3", new string[] { });
        var renewedCert = await _kvCertProvider.RenewCertificateAsync(initialCert);


        var data = Encoding.ASCII.GetBytes("Hello I'd like to sign this");
        //Sign something with first key and second key
        KeyVaultSignatureGenerator signing = new KeyVaultSignatureGenerator(new DefaultAzureCredential(), initialCert.KeyId, new X509Certificate2(initialCert.Cer));
        var encrypted1 = signing.SignData(data, HashAlgorithmName.SHA256);
        signing = new KeyVaultSignatureGenerator(new DefaultAzureCredential(), renewedCert.KeyId, new X509Certificate2(renewedCert.Cer));
        var encrypted2 = signing.SignData(data, HashAlgorithmName.SHA256);

        Assert.Equal(Convert.ToString(encrypted1), Convert.ToString(encrypted2));
    }
}