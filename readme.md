


```ps
$RG = 'CertificateAuthority'
$CA = 'rbklca'
$LOCATION = 'west europe'

az group create -g $RG -l $LOCATION
az deployment group create -g CertificateAuthority --template-file .\keyvault.bicep --parameters "{ 'name': { 'value': '$CA' }, 'location': { 'value': '$LOCATION' } }"

$policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=rbkl.local" -IssuerName "Self" -ValidityInMonths 6 -ReuseKeyOnRenewal -KeyNotExportable
Add-AzKeyVaultCertificate -VaultName $CA -Name RootCA -CertificatePolicy $policy

```