# Enable certificate for RDP Gateway
# For more script info see https://docs.certifytheweb.com/docs/script-hooks

param($result, [switch] $restartServices = $false)

# Apply certificate
$thumbprint = $result.ManagedItem.CertificateThumbprintHash

if ([string]::IsNullOrWhiteSpace($thumbprint)) {
	throw "Certificate thumbprint was not supplied."
}

$thumbprint = ($thumbprint -replace '\s', '').ToUpperInvariant()
$certHash = [byte[]]::new($thumbprint.Length / 2)

for ($i = 0; $i -lt $certHash.Length; $i++) {
	$certHash[$i] = [Convert]::ToByte($thumbprint.Substring($i * 2, 2), 16)
}

$gatewayNamespace = 'root/cimv2/TerminalServices'
$gatewaySettings = Get-CimInstance -Namespace $gatewayNamespace -ClassName Win32_TSGatewayServerSettings -ErrorAction Stop | Select-Object -First 1

if (-not $gatewaySettings) {
	throw "RD Gateway server settings were not found."
}

$setCertificateResult = Invoke-CimMethod -InputObject $gatewaySettings -MethodName SetCertificate -Arguments @{ CertHash = $certHash } -ErrorAction Stop

if ($setCertificateResult.ReturnValue -ne 0) {
	throw "SetCertificate failed with return value $($setCertificateResult.ReturnValue)."
}

$configureResult = Invoke-CimMethod -InputObject $gatewaySettings -MethodName Configure -ErrorAction Stop

if ($configureResult.ReturnValue -ne 0) {
	throw "Configure failed with return value $($configureResult.ReturnValue)."
}

# Optionally restart TSGateway and related service

if ($restartServices -eq $true)
{

	Restart-Service IAS -Force -ErrorAction Stop
	Restart-Service TSGateway -Force -ErrorAction Stop
	Restart-Service SSTPSvc -Force -ErrorAction Stop
	Write-Host "Services Restarted."
}
