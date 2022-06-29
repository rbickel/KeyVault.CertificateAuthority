using Azure.Identity;
using KeyVault.CertificateAuthority;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;


namespace KeyVaultCA
{
    class Program
    {
        private static string _keyVaultUrl="https://rbklkvssl.vault.azure.net/";
        static async Task Main(string[] args)
        {
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder
                    .AddFilter("Microsoft", LogLevel.Warning)
                    .AddFilter("System", LogLevel.Warning)
                    .AddFilter("KeyVault.CertificateAuthority", LogLevel.Debug)
                    .AddFilter("KeyVaultCertificateProvider", LogLevel.Debug)
                    .AddFilter("KeyVaultServiceClient", LogLevel.Debug)
                    .AddConsole();
            });

            await CreateCertificate(loggerFactory);
        }

        private static async Task CreateCertificate(ILoggerFactory loggerFactory)
        {
            ILogger logger = loggerFactory.CreateLogger<Program>();
            logger.LogInformation("KeyVaultCA app started.");

            var cred = new DefaultAzureCredential();
            

            //CREATE CERTIFICATE
            var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(_keyVaultUrl, cred, loggerFactory);
            
            //await kvCertProvider.CreateCACertificateAsync("pki-rbkl-io", "CN=pki.rbkl.io", 12, new string[]{"pki.rbkl.io"}, 3);
            
            //create CA            
            //await kvCertProvider.CreateCertificateAsync(CertificateType.CA, "ca3-rbkl-io", "ca3-rbkl-io", "CN=ca3-rbkl-io", 48, new string[]{"ca3-rbkl-io"}, 5);
            //await kvCertProvider.CreateCertificateAsync(CertificateType.Intermediate, "ca3-rbkl-io", "int-rbkl-io", "CN=int-rbkl-io", 48, new string[]{"int-rbkl-io"}, 3);
            //await kvCertProvider.CreateCertificateAsync(CertificateType.Tls, "int-rbkl-io", "tls-rbkl-io", "CN=tls-rbkl-io", 12, new string[]{"tls-rbkl-io"}, 0);

            await kvCertProvider.CreateCertificateWithDefaultsAsync(CertificateType.CA, "", "mycertificate-local", $"CN=mycertificate.local", new string[]{"mycertificate.local"});

            //RENEW CERTIFICATE
            // string certificateId = "https://rbklca.vault.azure.net/certificates/test/6c8df374a5c44f6d870709fb0057a96c";
            // var keyVaultUri = new Uri(certificateId);
            // string certificateName = "test";

            // var kvCertProvider2 = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider($"https://{keyVaultUri.Host}", cred, loggerFactory);
            // var certWithPolicy = await kvCertProvider2.GetCertificatePolicyAsync(certificateName);
            // //var existingCert = new X509Certificate2(policy.Cer);
            
            // var issuer = certWithPolicy.Properties.Tags["IssuerName"];
            // var issuerId = certWithPolicy.Properties.Tags["IssuerId"];
            // var issuerSubject = certWithPolicy.Policy.IssuerName;

            // await kvCertProvider2.RenewCertificateAsync(certWithPolicy, 12);


            // // Issue device certificate
            // var csr = Convert.FromBase64String("MIICxjCCAa4CAQAwGjEYMBYGA1UEAxMPdGVzdC5yYmtsLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAupxA+D09KNJRZ+kMxA7qUdD4bZlr/WeddtRmFur/nEV+SkGSf7aARd78jD+95WS4ydl9wA4icUmGsHA0IGA+9H/8vqfiEspQfp4e5rOhXnVUAwu9O8aRo8ln5CZ+VExtC3BUbjaLRYasmRAvPAix8JC1dj42cGH3H9Cs1yIKw1uV/HBu1QPzii0WgGh+Yd5NCkH9HGQEgmbxJQr48rwoIjv539kGYSpsoeMmsG23R4tS1MdXTKO97uC1cPV6F8FvKGWmpFs6Vk+mC15mnpKEK8ovoIhqql1Q5L+BzTN0dJJPzju7nbISwrFXeaFOiPmCOkRiEol43/nnn5yDqCP1LQIDAQABoGcwZQYJKoZIhvcNAQkOMVgwVjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBoGA1UdEQQTMBGCD3Rlc3QucmJrbC5sb2NhbDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQARIYFhIRiHyc8pHO5tOftQ0phaXmtCunteSV4bSypX1pLWkHLnLhz4TOdwM62P0TC7aEqa/srqbelWmDDhRNytdhlzaBijsld72sNvJmM4yo7vO2itR0Fn1kYysFmUOeVkvuKIZ/6ew0radWT7TgFHsPMnVhGUejBKh/Ifr2RADHGOySGPcO7Zq8YUP13DA7ZNoTPT0HWvQ7eIDKRjr1VJfPjAXEOGZmKMR95uasI/i0lR+c/Wu+r3pv+sWCK4R0roM0irIr9jrup1JYO7lNGxlu2OWVCl4bhPIaZhRI8G7+CfimCmO9Oe4d9kmH2aAgeYFq9UgwvPJJzXSyztJBF4");
            // var cert = await kvCertProvider.SignRequestAsync(csr, "CA", 12);

            // var signedRequest = Convert.ToBase64String(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.SerializedCert));
            // File.WriteAllText("test.cer", signedRequest);
            // logger.LogInformation("Device certificate was created successfully.");
        }
    }
}
