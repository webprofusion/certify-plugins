param($result, [switch] $restartServices = $false, [switch] $alternateTlsBinding = $false)
            
# https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-certificates-ad-fs-wap

Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $result.ManagedItem.CertificateThumbprintHash -Confirm:$false

Set-AdfsSslCertificate -Thumbprint $result.ManagedItem.CertificateThumbprintHash -ErrorAction Stop -Confirm:$false

# primary AD FS with Alternate TLS binding
if ( $alternateTlsBinding -eq $true) {
    Set-AdfsAlternateTlsClientBinding -Thumbprint $result.ManagedItem.CertificateThumbprintHash -ErrorAction Stop -Confirm:$false
} 

if ( $restartServices -eq $true) {

    Restart-Service WinHttpAutoProxySvc
    Restart-Service W3SVC
    Restart-Service adfssrv
}