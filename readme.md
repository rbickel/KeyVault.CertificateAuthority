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
New-AzResourceGroup -Name $RG -Location $LOCATION
$params = @{ 
    name = $CA
    location = $LOCATION 
}
$deployment = New-AzResourceGroupDeployment -ResourceGroupName $RG -TemplateFile .\keyvault.bicep -TemplateParameterObject $params

# Set Key Vault Administrator permission for current user (needed to generate CA)
$currentUserObjectId = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account).Id
Set-AzKeyVaultAccessPolicy -ObjectId $currentUserObjectId -VaultName $CA -PermissionsToCertificates all

# Create a non-exportable Self-Signed Root CA that can be used to generate client and server certificates
$CAName = "RootCA"
$CASan = "ca.local"
$policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=$CASan" -IssuerName "Self" -ValidityInMonths 48 -ReuseKeyOnRenewal -KeyNotExportable
$tags = @{
    IssuerName = $CAName
}
Add-AzKeyVaultCertificate -VaultName $CA -Name $CAName -CertificatePolicy $policy -Tag $tags

# Generate a test certificate
$san1 = "mysite.local"
$san2 = "*.mysite.local"
$certname = "mysite-local"
$code = $deployment.Outputs.functionKeys.Value
$uri = "https://$CA-func.azurewebsites.net/api/NewTlsCertificate?code=$code&name=$certname&subject=$san1&fqdn=$san1&fqdn=$san2"

Invoke-WebRequest -Uri $uri
#Your certificate should be created in Azure KeyVault if everything went through :)
```



