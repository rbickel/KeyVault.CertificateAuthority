// Default URL for triggering event grid function in the local environment.
// http://localhost:7071/runtime/webhooks/EventGrid?functionName={functionname}
using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Azure.EventGrid.Models;
using Microsoft.Azure.WebJobs.Extensions.EventGrid;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using KeyVault.CertificateAuthority;

namespace KeyVault.TlsAutoRenew
{
    public static class EventGridRenewCertificate
    {
        private static string _defaultKeyVaultUri= Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
        private static string _defaultDurationDays = Environment.GetEnvironmentVariable("DefaultCertificateDuration");
        private static string _defaultCA = Environment.GetEnvironmentVariable("DefaultKeyCACertificate");
        
        [FunctionName("RenewTlsCertificate")]
        public static async Task Run([EventGridTrigger] EventGridEvent eventGridEvent, ILogger log)
        {
            var data = (dynamic)eventGridEvent.Data;
            string certificateId = data.Id.ToString();
            string certificateName = data.ObjectName.ToString();
            log.LogDebug(eventGridEvent.Data.ToString());

            log.LogInformation($"Renewing {certificateName}");
            var keyVaultUri = new Uri(certificateId);
            var kvCertProvider2 = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider($"https://{keyVaultUri.Host}", log);
            var certWithPolicy = await kvCertProvider2.GetCertificatePolicyAsync(certificateName);
            //var existingCert = new X509Certificate2(policy.Cer);
            
            var issuer = certWithPolicy.Properties.Tags["IssuerName"];

            await kvCertProvider2.RenewCertificateAsync(certWithPolicy, int.Parse(_defaultDurationDays));
            log.LogInformation($"Certificate {certWithPolicy.Name} renewed by {issuer} for {_defaultDurationDays} days");
        }
    }
}
