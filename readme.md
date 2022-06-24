


```powershell
$RG = 'CertificateAuthority4'
$CA = 'rbklca4'
$LOCATION = 'Switzerland North'

# Create the resource group and the KeyVault account
az group create -g $RG -l $LOCATION
az deployment group create -g $RG --template-file .\keyvault.bicep --parameters "{ 'name': { 'value': '$CA' }, 'location': { 'value': '$LOCATION' } }"

# Create a non-exportable Self-Signed Root CA that can be used to generate client and server certificates
$policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=rbkl.local" -IssuerName "Self" -ValidityInMonths 48 -ReuseKeyOnRenewal -KeyNotExportable
Add-AzKeyVaultCertificate -VaultName $CA -Name RootCA -CertificatePolicy $policy

```