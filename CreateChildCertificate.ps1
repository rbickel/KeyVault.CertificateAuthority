$CA = 'MyCertAuth01'
$name = 'child-child-contoso-com'

$policy = New-AzKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName "CN=contoso.com" -IssuerName "Unknown" -ValidityInMonths 6 -ReuseKeyOnRenewal -KeyNotExportable
$cert = Add-AzKeyVaultCertificate -VaultName $CA -Name $name -CertificatePolicy $policy
$csr = $cert.CertificateSigningRequest

#openssl genrsa -out mydevice.key 2048
#openssl req -new -key mydevice.key -out mydevice.csr
openssl req -in cert.csr -out mydevice.csr.der -outform DER

