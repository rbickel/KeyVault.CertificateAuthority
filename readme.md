# KeyVault Certificate Authority

The goal of this solution is to provide a basic `serverless PKI (primary key infrastructure)`. While KeyVault can create Self-Signed certificate and auto-renew them, those certificate are signed by themselves and not a valid certificate authority. The idea is to generate(renew) and sign X509 certificates using another KeyVault certifiate as issuer (private CA). The whole solution generate and renew certificates while never handling/moving any private key. No private key ever leave the KeyVault instance.

A KeyVault resource is deployed to store/sign certificates, and Azure function to issue child certificates and renew them, and an Event Grid subscription to autmatically renew certificates before expiration.

![solution_design](https://user-images.githubusercontent.com/11852796/175933489-65a86f36-0eb0-4733-9034-9343a81d108c.png)

## Get started

Every stage below needs to run sequentially in the same console environment and this specific order. Splitted in different code section for clarity

### Define environment settings
```powershell
#powershell snippet
#replace values below or use them as is to give a try.

$RG = 'mykeyvaultauthority'  #resource group name
$CA = "kv$(Get-Random)"  #keyvault+resources name
$LOCATION = 'switzerland north'  #region

```
### Create KeyVault, Azure Function, Event Grid topic, Event Grid subscriptiom
```powershell
#powershell snippet
# Create the resource group and the KeyVault account
New-AzResourceGroup -Name $RG -Location $LOCATION
$params = @{ 
    name = $CA
    location = $LOCATION
    functionsPackage = 'https://github.com/rbickel/KeyVault.CertificateAuthority/releases/download/0.2.0/KeyVault.CertificateAuthority.0.2.0.zip'
}
$deployment = New-AzResourceGroupDeployment -ResourceGroupName $RG -TemplateFile .\keyvault.bicep -TemplateParameterObject $params
```
### Generate a CA and a a signed certificate with the Azure Function
```powershell
#powershell snippet
# Retrieve the function authorization code
$code = $deployment.Outputs.functionKeys.Value

$CAName="myca-local"
$CASubject="myca.local"
$uri = "https://$CA-func.azurewebsites.net/api/NewTlsCertificate?code=$code&name=$CAName&subject=$CASubject&san=$CASubject&ca=true"

#Calls the Azure function to generate the CA certificate
Invoke-WebRequest -Uri $uri

# Generate a test certificate
$certname = "mysite-local"
$san1 = "mysite.local"
$san2 = "*.mysite.local"
$uri = "https://$CA-func.azurewebsites.net/api/NewTlsCertificate?code=$code&name=$certname&issuer=$CAName&subject=$san1&san=$san1&san=$san2"

#Calls the Azure function to generate the TLS certificate signed by our CA
Invoke-WebRequest -Uri $uri
#Your certificate should be created in Azure KeyVault if everything went through :)
```

## Limitations and issues

- As the bicep template defines access policies, deployment on an existing keyvault will override existing access policies
- The Azure function is deployed using a consumption plan. KeyVault must therefore authorize public access (The bicep template doesn't configure KV Firewall)
- You can generate a client certificate with any existing certificate with its private key in the KeyVault . However, only the parent issuer certificate is bundled in the client PEM/PFX certificate (not the complete chain).

