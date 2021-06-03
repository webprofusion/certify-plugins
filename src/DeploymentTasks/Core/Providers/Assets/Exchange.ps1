# This script enables the use of the newly retrieved and stored certificate with common Exchange services
# For more script info see https://docs.certifytheweb.com/docs/script-hooks

param($result, $services, [switch] $cleanupPreviousCerts = $false, [switch] $addDoNotRequireSslFlag = $false)

# enable powershell snap-in for Exchange 2010 upwards
Add-PSSnapIn Microsoft.Exchange.Management.PowerShell.E2010

Write-Host "Enabling Certificate for Exchange services.."
		


if ($addDoNotUseSslFlag -eq $true)
{
	$args = @{ 
		Thumbprint = $result.ManagedItem.CertificateThumbprintHash; 
		Services = $services; 
		Force = $true;
		ErrorAction = Stop;
	}

	$args["DoNotRequireSsl"]= $true

	# use optional args
	Enable-ExchangeCertificate @args
} else {
	# tell Exchange which services to use this certificate for, force accept certificate to avoid command line prompt
	Enable-ExchangeCertificate -Thumbprint $result.ManagedItem.CertificateThumbprintHash -Services $services -Force -ErrorAction Stop
}

Write-Host "Certificate set OK for services."

if ($cleanupPreviousCerts -eq $true)
{
	Write-Host "Cleaning up previous certs in Exchange"
	
	Get-ExchangeCertificate -DomainName $Certificate.Subject.split("=")[1] | Where-Object -FilterScript { $_.Thumbprint -ne $NewCertThumbprint} | Remove-ExchangeCertificate -Confirm:$false
}