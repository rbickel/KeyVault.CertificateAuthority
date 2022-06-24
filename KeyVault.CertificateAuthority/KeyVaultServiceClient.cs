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

        internal async Task<X509Certificate2> CreateCertificateAsync(
                string issuerCertificateName,
                string certificateName,
                string subject,
                string[]SAN,
                DateTime notBefore,
                DateTime notAfter,
                int keySize,
                int hashSize,
                int certPathLength,
                CancellationToken ct = default)
        {
                var san = new SubjectAlternativeNames();
                foreach(var s in SAN)
                {
                    san.DnsNames.Add(s);
                }

                return await CreateCertificateAsync(issuerCertificateName, certificateName, subject, san, notBefore, notAfter, keySize, hashSize, certPathLength);
        }   

        internal async Task<X509Certificate2> CreateCertificateAsync(
                string issuerCertificateName,
                string certificateName,
                string subject,
                SubjectAlternativeNames san,
                DateTime notBefore,
                DateTime notAfter,
                int keySize,
                int hashSize,
                int certPathLength,
                bool caCert = false,
                bool rootCACert = false,
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

            string caTempCertIdentifier = null;

            try
            {
                //retrieve issuerCertificateInfo
                var signingCertiWithPolicy = await _certificateClient.GetCertificateAsync(issuerCertificateName);
                var signingCert = new X509Certificate2(signingCertiWithPolicy.Value.Cer);

                // create policy for unknown issuer and reuse key
                var policyUnknownReuse = CreateCertificatePolicy(subject, san, keySize, rootCACert, true, !caCert);
                var tags = CreateCertificateTags(signingCertiWithPolicy.Value.KeyId.ToString(), issuerCertificateName, false);

                // create the CSR
                _logger.LogDebug("Starting to create the CSR.");
                var createResult = await _certificateClient.StartCreateCertificateAsync(certificateName, policyUnknownReuse, true, tags, ct).ConfigureAwait(false);

                if (createResult.Properties.Csr == null)
                {
                    throw new Exception("Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                _logger.LogDebug("Decode the CSR and verify consistency.");
                var pkcs10CertificationRequest = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(createResult.Properties.Csr);
                var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
                if (createResult.Properties.Csr == null ||
                    pkcs10CertificationRequest == null ||
                    !pkcs10CertificationRequest.Verify())
                {
                    _logger.LogError("Invalid CSR.");
                    throw new Exception("Invalid CSR.");
                }
               
                var publicKey = KeyVaultCertFactory.GetRSAPublicKey(info.SubjectPublicKeyInfo);

                var dnsNames = san?.DnsNames ?? new List<string>();
                // create the certificate
                _logger.LogDebug("Create the certificate.");
                var signedcert = await KeyVaultCertFactory.CreateSignedCertificate(
                    subject,
                    (ushort)keySize,
                    notBefore,
                    notAfter,
                    (ushort)hashSize,
                    signingCert,
                    publicKey,
                    new KeyVaultSignatureGenerator(Credential, signingCertiWithPolicy.Value.KeyId, signingCert),
                    dnsNames,
                    caCert
                    );

                // merge Root CA cert with the signed certificate
                _logger.LogDebug("Merge Root CA certificate with the signed certificate.");
                MergeCertificateOptions options = new MergeCertificateOptions(certificateName, new[] { signedcert.Export(X509ContentType.Pkcs12) });
                var mergeResult = await _certificateClient.MergeCertificateAsync(options);

                return new X509Certificate2(mergeResult.Value.Cer);
            }
            catch (Exception ex)
            {
                _logger.LogError("Failed to create new certificate: {ex}.", ex);
                throw;
            }
            finally
            {
                if (caTempCertIdentifier != null)
                {
                    try
                    {
                        // disable the temp cert for self signing operation
                        _logger.LogDebug("Disable the temporary certificate for self signing operation.");

                        Response<KeyVaultCertificateWithPolicy> certificateResponse = _certificateClient.GetCertificate(caTempCertIdentifier);
                        KeyVaultCertificateWithPolicy certificate = certificateResponse.Value;
                        CertificateProperties certificateProperties = certificate.Properties;
                        certificateProperties.Enabled = false;
                        await _certificateClient.UpdateCertificatePropertiesAsync(certificateProperties);
                    }
                    catch
                    {
                        // intentionally ignore error
                    }
                }
            }
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

        private Dictionary<string, string> CreateCertificateTags(string id, string issuerName, bool trusted)
        {
            var tags = new Dictionary<string, string>();
            tags.Add("IssuerId", id);
            tags.Add("IssuerName", issuerName);
            tags.Add("Trusted", trusted.ToString());
            _logger.LogDebug("Created certificate tags for certificate with id {id} and trusted flag set to {trusted}.", id, trusted);
            return tags;
        }

        private CertificatePolicy CreateCertificatePolicy(
            string subject,
            SubjectAlternativeNames san,
            int keySize,
            bool selfSigned,
            bool reuseKey = false,
            bool exportable = false)
        {
            var issuerName = selfSigned ? "Self" : "Unknown";
            var policy = new CertificatePolicy(issuerName, subject)
            {
                Exportable = exportable,
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