// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Org.BouncyCastle.Pkcs;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;

namespace KeyVault.CertificateAuthority
{
    public class KeyVaultCertificateProvider : IKeyVaultCertificateProvider
    {
        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly ILogger _logger;

        #region Get KeyVaultCertificateProvider instance
        public static KeyVaultCertificateProvider GetKeyVaultCertificateProvider(string keyVaultUrl)
        {
            var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions());

            using ILoggerFactory loggerFactory =
                LoggerFactory.Create(builder =>
                    builder.AddSimpleConsole(options =>
                    {
                        options.IncludeScopes = true;
                        options.SingleLine = true;
                        options.TimestampFormat = "hh:mm:ss ";
                    }));
            return new KeyVaultCertificateProvider(new KeyVaultServiceClient(keyVaultUrl, credential, loggerFactory), loggerFactory);
        }

        public static KeyVaultCertificateProvider GetKeyVaultCertificateProvider(string keyVaultUrl, DefaultAzureCredential credential, ILoggerFactory loggerFactory)
        {
            return new KeyVaultCertificateProvider(new KeyVaultServiceClient(keyVaultUrl, credential, loggerFactory), loggerFactory);
        }

        public static KeyVaultCertificateProvider GetKeyVaultCertificateProvider(string keyVaultUrl, ILogger logger)
        {
            return new KeyVaultCertificateProvider(new KeyVaultServiceClient(keyVaultUrl, new DefaultAzureCredential(), logger), logger);
        }

        private KeyVaultCertificateProvider(KeyVaultServiceClient keyVaultServiceClient, ILoggerFactory loggerFactory)
        {
            _keyVaultServiceClient = keyVaultServiceClient;
            _logger = loggerFactory.CreateLogger(nameof(KeyVaultCertificateProvider));
        }

        private KeyVaultCertificateProvider(KeyVaultServiceClient keyVaultServiceClient, ILogger logger)
        {
            _keyVaultServiceClient = keyVaultServiceClient;
            _logger = logger;
        }

        #endregion

        public async Task<KeyVaultCertificateWithPolicy> CreateCertificateWithDefaultsAsync(CertificateType certificateType, string issuerCertificateName, string certificateName, string subject, string[] san)
        {
            int certPathLength = 0;
            int durationInMonths = 12;
            switch (certificateType)
            {
                case CertificateType.CA:
                    durationInMonths = 48;
                    certPathLength = 5;
                    break;
                case CertificateType.Intermediate:
                    durationInMonths = 48;
                    certPathLength = 3;
                    break;
            }

            var notBefore = DateTime.UtcNow.Date;
            return await _keyVaultServiceClient.CreateCertificateAsync(
                    certificateType,
                    issuerCertificateName,
                    certificateName,
                    subject,
                    san,
                    durationInMonths,
                    KeyVaultCertFactory.DefaultKeySize,
                    KeyVaultCertFactory.DefaultHashSize,
                    certPathLength);
            _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created succsessfully.", issuerCertificateName, 0);
        }

        public async Task<KeyVaultCertificateWithPolicy> CreateCertificateAsync(CertificateType type, string issuerCertificateName, string certificateName, string subject, int durationInMonths, string[] san, int certPathLength)
        {
            return await _keyVaultServiceClient.CreateCertificateAsync(
                    type,
                    issuerCertificateName,
                    certificateName,
                    subject,
                    san,
                    durationInMonths,
                    KeyVaultCertFactory.DefaultKeySize,
                    KeyVaultCertFactory.DefaultHashSize,
                    certPathLength);
            _logger.LogInformation("A new certificate with issuer name {name} and path length {path} was created succsessfully.", issuerCertificateName, 0);
        }

        public async Task<KeyVaultCertificateWithPolicy> RenewCertificateAsync(KeyVaultCertificateWithPolicy certWithPolicy)
        {
            if (certWithPolicy.Properties.Tags.TryGetValue("IssuerName", out string issuerName) && certWithPolicy.Properties.Tags.TryGetValue("CertificateType", out string type))
            {
                Enum.TryParse<CertificateType>(type, true, out CertificateType certificateType);

                int certPathLength = 0;
                int duration = 12;
                switch (certificateType)
                {
                    case CertificateType.CA:
                        duration = 48;
                        certPathLength = 5;
                        break;
                    case CertificateType.Intermediate:
                        duration = 48;
                        certPathLength = 3;
                        break;
                }


                var san = certWithPolicy.Policy.SubjectAlternativeNames.DnsNames.ToArray();
                return await _keyVaultServiceClient.CreateCertificateAsync(
                        certificateType,
                        issuerName,
                        certWithPolicy.Name,
                        certWithPolicy.Policy.Subject,
                        san,
                        duration,
                        KeyVaultCertFactory.DefaultKeySize,
                        KeyVaultCertFactory.DefaultHashSize,
                        certPathLength,
                        true);

                _logger.LogInformation("Certificate with issuer name {name} and path length {path} was created succsessfully.", issuerName, certPathLength);
            }
            else
            {
                _logger.LogWarning($"Tag 'IssuerName' with the issuing certificate is missing on certificate {certWithPolicy.Id}");
                return null;
            }
        }


        public async Task<X509Certificate2> GetCertificateAsync(string certificateName)
        {
            var certBundle = await _keyVaultServiceClient.GetCertificateAsync(certificateName).ConfigureAwait(false);
            return new X509Certificate2(certBundle.Value.Cer);
        }

        public async Task<KeyVaultCertificateWithPolicy> GetCertificatePolicyAsync(string certificateName)
        {
            var certBundle = await _keyVaultServiceClient.GetCertificateAsync(certificateName).ConfigureAwait(false);
            return certBundle.Value;
        }

        public async Task<IList<X509Certificate2>> GetPublicCertificatesByName(IEnumerable<string> certNames)
        {
            var certs = new List<X509Certificate2>();

            foreach (var issuerName in certNames)
            {
                _logger.LogDebug("Call GetPublicCertificatesByName method with following certificate name: {name}.", issuerName);
                var cert = await GetCertificateAsync(issuerName).ConfigureAwait(false);

                if (cert != null)
                {
                    certs.Add(cert);
                }
            }

            return certs;
        }
    }
}