// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVault.CertificateAuthority
{
    /// <summary>
    /// The KeyVault service client.
    /// </summary>
    public class KeyVaultServiceClient
    {
        private CertificateClient _certificateClient;
        private readonly ILogger _logger;
        public DefaultAzureCredential Credential { get; set; }

        /// <summary>
        /// Create the certificate client for managing certificates in Key Vault, using developer authentication locally or managed identity in the cloud.
        /// </summary>
        public KeyVaultServiceClient(string KeyVaultUrl, DefaultAzureCredential credential, ILoggerFactory loggerFactory)
        {
            _certificateClient = new CertificateClient(new Uri(KeyVaultUrl), credential);
            _logger = loggerFactory.CreateLogger(nameof(KeyVaultServiceClient));
            Credential = credential;
        }

        public KeyVaultServiceClient(string KeyVaultUrl, DefaultAzureCredential credential, ILogger logger)
        {
            _certificateClient = new CertificateClient(new Uri(KeyVaultUrl), credential);
            _logger = logger;
            Credential = credential;
        }


        internal async Task<KeyVaultCertificateWithPolicy> CreateCertificateWithDefaultAsync(
                CertificateType type,
                string issuerCertificateName,
                string certificateName,
                string subject,
                string[] SAN)
        {
            int duration = type == CertificateType.Tls ? 12 : 48;
            int certPathLength = type == CertificateType.Tls ? 0 : 5;
            return await CreateCertificateAsync(
                type,
                issuerCertificateName,
                certificateName,
                subject,
                SAN,
                duration,
                2048,
                256,
                certPathLength
                );
        }


        internal async Task<KeyVaultCertificateWithPolicy> CreateCertificateAsync(
                CertificateType type,
                string issuerCertificateName,
                string certificateName,
                string subject,
                string[] SAN,
                int durationInMonths,
                int keySize,
                int hashSize,
                int certPathLength,
                bool renew = false,
                CancellationToken ct = default)
        {
            try
            {
                // delete pending operations
                _logger.LogDebug("Deleting pending operations for certificate id {id}.", certificateName);
                var op = await _certificateClient.GetCertificateOperationAsync(certificateName);
                await op.DeleteAsync();
            }
            catch
            {
                // intentionally ignore errors 
            }

            Uri signingCertificateKeyId = null;
            X509Certificate2 signingCertificate = null;

            //Retrieve existing signing certificate
            if(type == CertificateType.Intermediate || type == CertificateType.Tls || renew)
            {
                var signingCertificateRequest = await _certificateClient.GetCertificateAsync(issuerCertificateName);
                signingCertificateKeyId = signingCertificateRequest.Value.KeyId;
                signingCertificate = new X509Certificate2(signingCertificateRequest.Value.Cer);
            }
            else
            {
                //Initial Root CA certificate
                //Create a new CSR self-signed to use as self-signing CA authority
                var initialPolicy = CreateCertificatePolicy(subject, SAN, durationInMonths, keySize, true, true);
                var selfSignedCsr = await _certificateClient.StartCreateCertificateAsync(certificateName, initialPolicy, true, null, ct).ConfigureAwait(false);
                await selfSignedCsr.WaitForCompletionAsync();

                if (!selfSignedCsr.HasCompleted)
                {
                    _logger.LogError("Failed to create new key pair.");
                    throw new Exception("Failed to create new key pair.");
                }

                signingCertificateKeyId = selfSignedCsr.Value.KeyId;
                signingCertificate = new X509Certificate2(selfSignedCsr.Value.Cer);
            }

            //default CA certificate policy
            var certificatePolicy = CreateCertificatePolicy(subject, SAN, durationInMonths, keySize, false, true);
            switch (type)
            {
                case CertificateType.Tls:
                    certificatePolicy = CreateCertificatePolicy(subject, SAN, durationInMonths, keySize, false, false);
                    break;
                case CertificateType.Intermediate:
                case CertificateType.CA:
                    certificatePolicy = CreateCertificatePolicy(subject, SAN, durationInMonths, keySize, false, true);
                    break;
            }

            //Initiate teh new certificate CSR
            var tags = CreateCertificateTags(type, signingCertificateKeyId.ToString(), issuerCertificateName, true);
            var newCertificateOperation = await _certificateClient.StartCreateCertificateAsync(certificateName, certificatePolicy, true, tags, ct).ConfigureAwait(false);

            var createdCertificateBundle = await _certificateClient.GetCertificateAsync(certificateName);
            var pkcs10CertificationRequest = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(newCertificateOperation.Properties.Csr);
            var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
            if (newCertificateOperation.Properties.Csr == null ||
                pkcs10CertificationRequest == null ||
                !pkcs10CertificationRequest.Verify())
            {
                _logger.LogError("Invalid CSR.");
                throw new Exception("Invalid CSR.");
            }

            // create the self signed root CA certificate
            _logger.LogDebug("Create and sign the certificate");
            var publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);
            var signedcert = await KeyVaultCertFactory.CreateSignedCertificate(
                type,
                subject,
                (ushort)keySize,
                DateTime.Now.Date,
                DateTime.Now.Date.AddMonths(durationInMonths),
                (ushort)hashSize,
                signingCertificate,
                publicKey,
                new KeyVaultSignatureGenerator(Credential, signingCertificateKeyId, signingCertificate),
                SAN,
                certPathLength);

            _logger.LogDebug("Merge the signed certificate with the KeyVault certificate");
            MergeCertificateOptions options = new MergeCertificateOptions(certificateName, new[] { signingCertificate.Export(X509ContentType.Pkcs12), signedcert.Export(X509ContentType.Pkcs12) });
            var mergeResult = await _certificateClient.MergeCertificateAsync(options);

            return mergeResult.Value;
        }

        /// <summary>
        /// Get Certificate with Policy from Key Vault.
        /// </summary>
        internal async Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string certName, CancellationToken ct = default)
        {
            return await _certificateClient.GetCertificateAsync(certName, ct).ConfigureAwait(false);
        }

        internal async Task<Response<KeyVaultCertificateWithPolicy>> MergeSignedRequestCertificate(string certificateName, IEnumerable<byte[]> x509Certificates)
        {
            return await _certificateClient.MergeCertificateAsync(new MergeCertificateOptions(certificateName, x509Certificates));
        }

        /// <summary>
        /// Get certificate versions for given certificate name.
        /// </summary>
        internal async Task<int> GetCertificateVersionsAsync(string certName)
        {
            var versions = 0;
            await foreach (CertificateProperties cert in _certificateClient.GetPropertiesOfCertificateVersionsAsync(certName))
            {
                versions++;
            }
            return versions;
        }

        private Dictionary<string, string> CreateCertificateTags(CertificateType type, string id, string issuerName, bool trusted)
        {
            var tags = new Dictionary<string, string>();
            tags.Add("IssuerId", id);
            tags.Add("IssuerName", issuerName);
            tags.Add("CertificateType", type.ToString());
            _logger.LogDebug("Created certificate tags for certificate with id {id} and trusted flag set to {trusted}.", id, trusted);
            return tags;
        }

        private CertificatePolicy CreateCertificatePolicy(
            string subject,
            string[] san,
            int duration,
            int keySize,
            bool selfSigned,
            bool reuseKey = false,
            bool exportable = false)
        {
            SubjectAlternativeNames names = new SubjectAlternativeNames();
            foreach (var s in san)
            {
                names.DnsNames.Add(s);
            }
            var issuerName = selfSigned ? "Self" : "Unknown";
            
            var policy = new CertificatePolicy(issuerName, subject, names)
            {
                Exportable = exportable,
                ValidityInMonths = duration,
                KeySize = keySize,
                KeyType = "RSA",
                ReuseKey = reuseKey,
                ContentType = CertificateContentType.Pkcs12
            };

            _logger.LogDebug("Created certificate policy for certificate with issuer name {issuerName}, self signed {selfSigned} and reused key {reuseKey}.", issuerName, selfSigned, reuseKey);
            return policy;
        }
    }
}