# This script enables the use of the newly retrieved and stored certificate with common Exchange services
# For more script info see https://docs.certifytheweb.com/docs/script-hooks

param($result, $services, [switch] $cleanupPreviousCerts = $false, [switch] $addDoNotRequireSslFlag = $false)

# stop at the first error, so a failure to load the snap-in isn't followed by misleading output
$ErrorActionPreference = 'Stop'

# enable powershell snap-in for Exchange 2010 upwards (requires Windows PowerShell 5.1)
Add-PSSnapIn Microsoft.Exchange.Management.PowerShell.E2010

Write-Host "Enabling Certificate for Exchange services.."

# tell Exchange which services to use this certificate for, force accept certificate to avoid command line prompt
$enableArgs = @{
	Thumbprint = $result.ManagedItem.CertificateThumbprintHash
	Services = $services
	Force = $true
}

if ($addDoNotRequireSslFlag -eq $true)
{
	$enableArgs["DoNotRequireSsl"] = $true
}

Enable-ExchangeCertificate @enableArgs

Write-Host "Certificate set OK for services."

if ($cleanupPreviousCerts -eq $true)
{
	Write-Host "Cleaning up previous certs in Exchange"
	
	Get-ExchangeCertificate -DomainName $Certificate.Subject.split("=")[1] | Where-Object -FilterScript { $_.Thumbprint -ne $NewCertThumbprint} | Remove-ExchangeCertificate -Confirm:$false
}