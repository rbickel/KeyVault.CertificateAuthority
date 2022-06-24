# KeyVault Certificate Authority

The goal of thei project is to provide a mecanism to issue CA signed certificate internally, leveraging KeyVault. While KeyVault can create Self-Signed certificate and auto-renew them, those certificate may not be used in certain services.

The idea is to generate and renew X509 certificates using a CA certificate generated in KeyVault. Using this approach, generated certificates may be used in some services, that usually don't support self-signed certificates.

The whole solution generate and renew certificates while never handling any private key. No private key ever leave the KeyVault isntance.

## Get started

```powershell
$RG = '<resource group name>'
$CA = '<keyvault name>'
$LOCATION = '<region>'

# Create the resource group and the KeyVault account
az group create -g $RG -l $LOCATION
az deployment group create -g $RG --template-file .\keyvault.bicep --parameters "{ 'name': { 'value': '$CA' }, 'location': { 'value': '$LOCATION' } }"

# Set Key Vault Administrator permission for current user (needed to generate CA)
$currentUserObjectId = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account).Id
New-Az
Set-AzKeyVaultAccessPolicy -ObjectId $currentUserObjectId -VaultName $CA -PermissionsToCertificates all

# Create a non-exportable Self-Signed Root CA that can be used to generate client and server certificates
$CAName = "RootCA"
$CASan = "ca.local"
$policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=$CASan" -IssuerName "Self" -ValidityInMonths 48 -ReuseKeyOnRenewal -KeyNotExportable
Add-AzKeyVaultCertificate -VaultName $CA -Name $CAName -CertificatePolicy $policy

# Generate a test certificate
$san = "mysite.local"
$certname = "mysite-local"
$uri = "https://rbklca4-func.azurewebsites.net/api/NewTlsCertificate?name=$certname&subject=$san&fqdn=$san&code=pv5b7r0Qjdj1qJ6bh66kvshrJTbpCtnVGmb2urrvm-WrAzFulamUhg=="

Invoke-WebRequest -Uri $uri

```



