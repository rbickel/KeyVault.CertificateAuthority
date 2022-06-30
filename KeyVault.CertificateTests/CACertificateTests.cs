using KeyVault.CertificateAuthority;

namespace KeyVault.CertificateTests;

public class CACertificateTests
{
    [Fact(DisplayName="CA should not have an exportable key")]
    public async Task CACertificates_KeysExportable_ReturnFalse()
    {
        var _keyVaultUrl= Config.Instance.KeyVaultUri;
        var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(_keyVaultUrl);
        var result = await kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "test-ca", "test-ca", "CN=test-ca", new string[]{});

        Assert.False(result.Policy.Exportable);
    }

    [Fact(DisplayName="CA should reuse keys")]
    public async Task CACertificates_ReuseKeys_ReturnTrue()
    {
        var _keyVaultUrl= Config.Instance.KeyVaultUri;
        var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(_keyVaultUrl);
        var result = await kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "test-ca2", "test-ca2", "CN=test-ca2", new string[]{});

        Assert.True(result.Policy.ReuseKey);
    }    
}