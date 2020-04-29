param($result, [switch] $restartServices = $false)

Import-Module RemoteAccess

# get cert object to apply by thumbprint, assumes My cert store, TODO: could check Web Hosting if get null result
$Cert = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse | Where-Object {$_.thumbprint -eq $result.ManagedItem.CertificateThumbprintHash} | Select-Object -f 1

if ( $restartServices -eq $true) {
	Stop-Service RemoteAccess
}

Set-RemoteAccess -SslCertificate $Cert

if ( $restartServices -eq $true) {
	Start-Service RemoteAccess
}