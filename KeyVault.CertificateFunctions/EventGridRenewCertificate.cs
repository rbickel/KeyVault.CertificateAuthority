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

namespace KeyVault.CertificateFunctions
{
    public static class EventGridRenewCertificate
    {
        [FunctionName(nameof(EventRenewCertificate))]
        public static async Task EventRenewCertificate([EventGridTrigger] EventGridEvent eventGridEvent, ILogger log)
        {
            string defaultKeyVaultUri= Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
            string defaultDurationDays = Environment.GetEnvironmentVariable("DefaultCertificateDuration");
            string defaultCA = Environment.GetEnvironmentVariable("DefaultKeyCACertificate");

            var data = (dynamic)eventGridEvent.Data;
            string certificateId = data.Id.ToString();
            string certificateName = data.ObjectName.ToString();
            log.LogDebug(eventGridEvent.Data.ToString());

            log.LogInformation($"Renewing {certificateName}");
            var keyVaultUri = new Uri(certificateId);
            var kvCertProvider2 = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider($"https://{keyVaultUri.Host}", log);
            var certWithPolicy = await kvCertProvider2.GetCertificatePolicyAsync(certificateName);
            //var existingCert = new X509Certificate2(policy.Cer);
            
            var result = await kvCertProvider2.RenewCertificateAsync(certWithPolicy);
            log.LogInformation($"Certificate {result.Name} renewed by {result.Properties.Tags["IssuerName"]} for {result.Policy.ValidityInMonths} months");
        }
    }
}
