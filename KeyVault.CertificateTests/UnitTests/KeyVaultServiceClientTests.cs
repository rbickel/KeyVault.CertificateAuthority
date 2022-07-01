using Moq;
using KeyVault.CertificateAuthority;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using Azure.Core;
using Azure;

namespace KeyVault.CertificateTests;


public class KeyVaultServiceClientTests
{
    private ILogger _logger;
    public KeyVaultServiceClientTests()
    {
        using ILoggerFactory loggerFactory =
            LoggerFactory.Create(builder =>
                builder.AddSimpleConsole(options =>
                {
                    options.IncludeScopes = true;
                    options.SingleLine = true;
                    options.TimestampFormat = "hh:mm:ss ";
                }));
        _logger = loggerFactory.CreateLogger(nameof(KeyVaultServiceClientTests));
    }

    [Fact]
    public async Task KeyVaultServiceClientTests2()
    {
        var policy = new Mock<KeyVaultCertificateWithPolicy>();
        policy.SetupGet(x => x.Policy).Returns(new CertificatePolicy("test", "CN=test")
        {
            Exportable = true,
            KeySize = 2048,
            KeyType = "RSA",
            ReuseKey = false,
            ContentType = "application/x-pkcs12"
        });
        var response = new Mock<Response<KeyVaultCertificateWithPolicy>>();
        response.SetupGet(x => x.Value).Returns(policy.Object);

        var certClient = new Mock<CertificateClient>();
        certClient.Setup(x => 
            x.GetCertificateAsync(It.IsAny<string>(), default))
        .ReturnsAsync(response.Object);
        var client = new KeyVaultServiceClient(certClient.Object, new DefaultAzureCredential(), _logger);

        var certificate = await client.CreateCertificateWithDefaultAsync(CertificateType.CA, "test", "test", "CN=test", new string[]{"test.test.test"});
        Assert.NotNull(certificate);
        Assert.False(certificate.Policy.Exportable.GetValueOrDefault());

    }
}