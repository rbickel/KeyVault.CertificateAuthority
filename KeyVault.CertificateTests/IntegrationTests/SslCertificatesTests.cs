using KeyVault.CertificateAuthority;

namespace KeyVault.CertificateTests;

public class SslCertificatesTests
{
    private KeyVaultCertificateProvider _kvCertProvider;

    public SslCertificatesTests()
    {
        var _keyVaultUrl = Config.Instance.KeyVaultUri;
        _kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(_keyVaultUrl);
    }

    [Fact(DisplayName = "SSL Certificates should have an exportable key")]
    public async Task SSLCertificates_KeysExportable_ReturnTrue()
    {
        await _kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "test-ca", "test-ca", "CN=test-ca", new string[] { "ca3-rbkl-io" });
        var result = await _kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.Tls, "test-ca", "test-ssl", "CN=test-ssl", new string[] { "test-ssl" });

        Assert.True(result.Policy.Exportable);
    }

}