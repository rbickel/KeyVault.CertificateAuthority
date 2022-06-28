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
using System.Text.RegularExpressions;

namespace KeyVault.TlsAutoRenew
{

    public static class HttpNewCertificate
    {

        private static Regex _nameRegex = new Regex("^[a-zA-Z0-9-]+$");
        //very basic SAN validation
        private static Regex _subjectRegex = new Regex(@"^[a-zA-Z0-9-*\.]+$");

        [FunctionName("NewTlsCertificate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string defaultKeyVaultUri = Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
            string defaultDurationDays = Environment.GetEnvironmentVariable("DefaultCertificateDuration");
            string defaultCADurationDays = Environment.GetEnvironmentVariable("DefaultCACertificateDuration");
            string defaultCA = Environment.GetEnvironmentVariable("DefaultKeyCACertificate");

            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];
            string subject = req.Query["subject"];
            string[] san = req.Query["san"];
            string issuer = req.Query["issuer"];
            bool.TryParse(req.Query["ca"], out bool ca);


            //parameters validation
            if (!_nameRegex.Match(name ?? string.Empty).Success)
            {
                // does not match
                return new ObjectResult($"Invalid certificate name provided. Must match {_nameRegex}")
                {
                    StatusCode = 400
                };
            }

            //parameters validation
            if (!ca && !_nameRegex.Match(issuer ?? string.Empty).Success)
            {
                // does not match
                return new ObjectResult($"Invalid isser name provided. Must match {_nameRegex}")
                {
                    StatusCode = 400
                };
            }            

            if (!_subjectRegex.Match(subject ?? string.Empty).Success)
            {
                // does not match
                return new ObjectResult($"Invalid subject name provided. Must match {_subjectRegex}")
                {
                    StatusCode = 400
                };
            }

            foreach (var s in san)
            {
                if (!_subjectRegex.Match(s ?? string.Empty).Success)
                {
                    // does not match
                    return new ObjectResult($"Invalid SAN name provided. Must match {_subjectRegex}")
                    {
                        StatusCode = 400
                    };
                }
            }

            var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(defaultKeyVaultUri, log);
            if (ca)
            {
                //generate CA certificate
                await kvCertProvider.CreateCACertificateAsync(name, $"CN={subject}", int.Parse(defaultCADurationDays), san);
            }
            else
            {
                await kvCertProvider.CreateCertificateAsync(issuer, name, $"CN={subject}", int.Parse(defaultDurationDays), san);
            }
            
            return new OkObjectResult(ca ? "CA Certificate generated successfully" : "Certificate generated successfully");
        }
    }
}
