using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Cryptography.X509Certificates;
using KeyVault.CertificateAuthority;
using System.Threading.Tasks;
using KeyVault.CertificateAuthority;
using Microsoft.Azure.EventGrid.Models;

namespace KeyVault.TlsAutoRenew
{
    public static class RenewTlsHttp
    {

        [FunctionName("RenewTlsHttp")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string certificateId = "https://rbklca.vault.azure.net/certificates/test/6c8df374a5c44f6d870709fb0057a96c";
            string certificateName = "test";

            var fakeEvent = new EventGridEvent();
            fakeEvent.Data = new {
                Id = certificateId,
                ObjectName = certificateName
            };
            await EventGridRenewCertificate.Run(fakeEvent, log);

            string responseMessage = "Certificate renewed successfully";
            return new OkObjectResult(responseMessage);
        }
    }
}
