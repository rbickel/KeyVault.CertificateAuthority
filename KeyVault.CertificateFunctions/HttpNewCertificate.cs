using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

using KeyVault.CertificateAuthority;
using Azure.Identity;
using System.Text.RegularExpressions;
using System.Net;
using AzureFunctions.Extensions.Swashbuckle.Attribute;
using AzureFunctions.Extensions.Swashbuckle;
using Azure;
using Azure.Security.KeyVault.Certificates;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;


namespace KeyVault.CertificateFunctions
{

    public static class HttpNewCertificate
    {
        private static Regex _nameRegex = new Regex("^[a-zA-Z0-9-]+$");
        //very basic SAN validation
        private static Regex _subjectRegex = new Regex(@"^[a-zA-Z0-9-*\.]+$");


        [FunctionName(nameof(GetKeyVaultCertificates))]
        [ProducesResponseType(typeof(CertificateModel[]), (int)HttpStatusCode.OK)]
        public static async Task<IActionResult> GetKeyVaultCertificates(
                    [HttpTrigger(AuthorizationLevel.Function, "get", Route = null)] HttpRequest req,
                    ILogger log)
        {
            string defaultKeyVaultUri = Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
            try
            {
                var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(defaultKeyVaultUri, log);
                var certificates = await kvCertProvider.GetCertificatesAsync();

                var dictionary = new Dictionary<string, CertificateModel>();
                foreach (var cert in certificates)
                {
                    dictionary.Add(cert.Name, new CertificateModel(cert));
                }
                foreach (var keypair in dictionary)
                {
                    var item = keypair.Value;
                    if (!string.IsNullOrEmpty(item.Issuer) && !string.Equals(item.Name, item.Issuer) && dictionary.ContainsKey(item.Issuer))
                    {
                        dictionary[item.Issuer].Certificates.Add(item);
                    }
                }

                var result = dictionary.Where(c => string.Equals(c.Value.Issuer, c.Value.Name)).ToDictionary(c => c.Key, c => c.Value);
                return new OkObjectResult(result);
            }
            catch (Azure.RequestFailedException ex)
            {
                return new BadRequestObjectResult(ex);
            }
            catch (Exception ex)
            {
                return new ObjectResult(ex)
                {
                    StatusCode = 500
                };
            }
        }


        [FunctionName(nameof(RenewTlsCertificate))]
        [ProducesResponseType(typeof(KeyVaultCertificateWithPolicy), (int)HttpStatusCode.OK)]
        [QueryStringParameter("name", "Name of the KeyVault certificate to renew ([a-zA-Z0-9-]) ", "mycertificate-local", Required = true)]
        public static async Task<IActionResult> RenewTlsCertificate(
                    [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
                    ILogger log)
        {
            string defaultKeyVaultUri = Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
            string defaultDurationMonths = Environment.GetEnvironmentVariable("DefaultCertificateDuration");
            string defaultCADurationMonths = Environment.GetEnvironmentVariable("DefaultCACertificateDuration");
            string defaultCA = Environment.GetEnvironmentVariable("DefaultKeyCACertificate");

            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];

            //parameters validation
            if (!_nameRegex.Match(name ?? string.Empty).Success)
            {
                // does not match
                return new ObjectResult($"Invalid certificate name provided. Must match {_nameRegex}")
                {
                    StatusCode = 400
                };
            }


            try
            {
                var kvCertProvider = KeyVaultCertificateProvider.GetKeyVaultCertificateProvider(defaultKeyVaultUri, log);
                var existingCertificate = await kvCertProvider.GetCertificatePolicyAsync(name);
                var renewedCertificate = await kvCertProvider.RenewCertificateAsync(existingCertificate);
                return new OkObjectResult(renewedCertificate);
            }
            catch (Azure.RequestFailedException ex)
            {
                return new BadRequestObjectResult(ex);
            }
            catch (Exception ex)
            {
                return new ObjectResult(ex)
                {
                    StatusCode = 500
                };
            }
        }

        [FunctionName(nameof(NewTlsCertificate))]
        [ProducesResponseType(typeof(KeyVaultCertificateWithPolicy), (int)HttpStatusCode.OK)]
        [QueryStringParameter("name", "Name of the KeyVault certificate ([a-zA-Z0-9-])", "mycertificate-local", Required = true)]
        [QueryStringParameter("subject", "Subject (fqdn or name)", "mycertificate.local", Required = true)]
        [QueryStringParameter("san", "Subject alternative names", "*.mycertificate.local", Required = false)]
        [QueryStringParameter("issuer", "Name of the KeyVault issuing certificate ([a-zA-Z0-9-])", "mycertificate-local", Required = false)]
        [QueryStringParameter("ca", "Is the certificate a certificate authority (root, intermediate) ?", false, Required = false)]
        public static async Task<IActionResult> NewTlsCertificate(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string defaultKeyVaultUri = Environment.GetEnvironmentVariable("DefaultKeyVaultUri");
            string defaultDurationMonths = Environment.GetEnvironmentVariable("DefaultCertificateDuration");
            string defaultCADurationMonths = Environment.GetEnvironmentVariable("DefaultCACertificateDuration");
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

            var certificateType = CertificateType.Tls;
            if (ca)
            {
                if (issuer == name || string.IsNullOrEmpty(issuer))
                {
                    certificateType = CertificateType.CA;
                    issuer = name;
                }
                else
                {
                    certificateType = CertificateType.Intermediate;
                }
            }

            try
            {
                var cert = await kvCertProvider.CreateCertificateWithDefaultsAsync(certificateType, issuer, name, $"CN={subject}", san);
                return new OkObjectResult(cert);
            }
            catch (Azure.RequestFailedException ex)
            {
                return new BadRequestObjectResult(ex);
            }
            catch (Exception ex)
            {
                return new ObjectResult(ex)
                {
                    StatusCode = 500
                };
            }
        }


    }
    public class CertificateModel
    {
        public CertificateModel(CertificateProperties cert)
        {
            this.Name = cert.Name;
            if (cert.Tags.ContainsKey("IssuerName"))
            {
                this.Issuer = cert.Tags["IssuerName"];
            }
            this.Tags = cert.Tags;
        }
        [JsonProperty(Order = 1)] 
        public string Name { get; set; }
        [JsonProperty(Order = 2)] 
        public string Issuer { get; set; }
        [JsonProperty(Order = 3)] 
        public IDictionary<string, string> Tags { get; set; }        
        [JsonProperty(Order = 4)] 
        public List<CertificateModel> Certificates = new List<CertificateModel>();
    }

}
