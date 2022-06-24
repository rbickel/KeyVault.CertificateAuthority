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
        private static string _defaultKeyVaultUri= Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
        private static string _defaultDurationDays = Environment.GetEnvironmentVariable("DefaultCertificateDuration");
        private static string _defaultCA = Environment.GetEnvironmentVariable("DefaultKeyCACertificate");

        [FunctionName("NewTlsCertificate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");    

            string name = req.Query["name"];
            string subject = req.Query["subject"];
            string[] fqdn = req.Query["fqdn"];
            string issuer = _defaultCA;

            //missing params validation
            var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(_defaultKeyVaultUri, log);
            await kvCertProvider.CreateCertificateAsync(issuer, name, $"CN={subject}",  int.Parse(_defaultDurationDays), fqdn, 1);

            string responseMessage = "Certificate generated successfully";
            return new OkObjectResult(responseMessage);
        }
    }
}
