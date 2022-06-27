# KeyVault Certificate Authority

The goal of this solution is to provide a basic `serverless PKI (primary key infrastructure)`. While KeyVault can create Self-Signed certificate and auto-renew them, those certificate are signed by themselves and not a certificate authority. The idea is to generate(renew) and sign X509 certificates using another KeyVault certifiate as issuer (private CA). The whole solution generate and renew certificates while never handling/moving any private key. No private key ever leave the KeyVault instance.

A KeyVault resource is deployed to store/sign certificates, and Azure function to issue child certificates and renew them, and an Event Grid subscription to autmatically renew certificates before expiration.

![solution_design](https://user-images.githubusercontent.com/11852796/175933489-65a86f36-0eb0-4733-9034-9343a81d108c.png)

## Get started

Every stage below needs to run sequentially in the same console environment and this specific order. Splitted in different code section for clarity

### Define environment settings
```powershell

$RG = '<resource group name>'
$CA = '<keyvault name>'
$LOCATION = '<region>'

```
### Create KeyVault, Azure Function, Event Grid topic, Event Grid subscriptiom
```powershell

# Create the resource group and the KeyVault account
New-AzResourceGroup -Name $RG -Location $LOCATION
$params = @{ 
    name = $CA
    location = $LOCATION 
}
$deployment = New-AzResourceGroupDeployment -ResourceGroupName $RG -TemplateFile .\keyvault.bicep -TemplateParameterObject $params

# Set Key Vault Administrator permission for current user (needed to generate CA)
$currentUserObjectId = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account).Id
Set-AzKeyVaultAccessPolicy -ObjectId $currentUserObjectId -VaultName $CA -PermissionsToCertificates all

```
### Generate a CA Certificate by using KV Self-Signed capabilities
```powershell

# Create a non-exportable Self-Signed Root CA that can be used to generate client and server certificates
$CAName = "RootCA"
$CASan = "ca.local"
$policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=$CASan" -IssuerName "Self" -ValidityInMonths 48 -ReuseKeyOnRenewal -KeyNotExportable
$tags = @{
    IssuerName = $CAName
}
Add-AzKeyVaultCertificate -VaultName $CA -Name $CAName -CertificatePolicy $policy -Tag $tags

```
### Generate a CA signed certificate with the Azure Function
```powershell

# Generate a test certificate
$san1 = "mysite.local"
$san2 = "*.mysite.local"
$certname = "mysite-local"
$code = $deployment.Outputs.functionKeys.Value
$uri = "https://$CA-func.azurewebsites.net/api/NewTlsCertificate?code=$code&name=$certname&subject=$san1&san=$san1&san=$san2"

Invoke-WebRequest -Uri $uri
#Your certificate should be created in Azure KeyVault if everything went through :)
```

## Limitations and issues

- As the bicep template defines access policies, deployment on an existing keyvault will override existing access policies
- The Azure function is deployed using a consumption plan. KeyVault must therefore authorize public access (The bicep template doesn't configure KV Firewall)
- You can generate a client certificate with any existing certificate with its private key in the KeyVault . However, only the parent issuer certificate is bundled in the client PEM/PFX certificate (not the complete chain).
- 

