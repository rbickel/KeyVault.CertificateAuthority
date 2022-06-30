using KeyVault.CertificateAuthority;

namespace KeyVault.CertificateTests;

public class SslCertificatesTests
{
    [Fact(DisplayName="SSL Certificates should have an exportable key")]
    public async Task SSLCertificates_KeysExportable_ReturnTrue()
    {
        var _keyVaultUrl = Config.Instance.KeyVaultUri;
        var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(_keyVaultUrl);
        await kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "test-ca", "test-ca", "CN=test-ca", new string[]{"ca3-rbkl-io"});
        var result = await kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.Tls, "test-ca", "test-ssl", "CN=test-ssl", new string[]{"test-ssl"});
        Assert.True(result.Policy.Exportable);
    }
}