using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using KeyVault.CertificateAuthority;
using Azure.Identity;

namespace KeyVault.TlsAutoRenew
{
    
    public static class HttpNewCertificate
    {
        [FunctionName("NewTlsCertificate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string defaultKeyVaultUri= Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
            string defaultDurationDays = Environment.GetEnvironmentVariable("DefaultCertificateDuration");
            string defaultCA = Environment.GetEnvironmentVariable("DefaultKeyCACertificate");

            log.LogInformation("C# HTTP trigger function processed a request.");    

            string name = req.Query["name"];
            string subject = req.Query["subject"];
            string[] fqdn = req.Query["fqdn"];
            string issuer = defaultCA;

            //missing params validation
            var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(defaultKeyVaultUri, log);
            await kvCertProvider.CreateCertificateAsync(issuer, name, $"CN={subject}",  int.Parse(defaultDurationDays), fqdn, 1);

            string responseMessage = "Certificate generated successfully";
            return new OkObjectResult(responseMessage);
        }
    }
}
