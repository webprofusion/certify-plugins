param($result, [switch] $restartServices = $false)
            
# https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-certificates-ad-fs-wap

Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $result.ManagedItem.CertificateThumbprintHash

Set-AdfsSslCertificate -Thumbprint $result.ManagedItem.CertificateThumbprintHash

# primary AD FS with Alternate TLS binding
# Set-AdfsAlternateTlsClientBinding -Thumbprint $result.ManagedItem.CertificateThumbprintHash

if ( $restartServices -eq $true) {

    Restart-Service WinHttpAutoProxySvc
    Restart-Service W3SVC
    Restart-Service adfssrv
}