# Enable certificate for RDP Listener Service
# For more script info see https://docs.certifytheweb.com/docs/script-hooks

# https://techcommunity.microsoft.com/t5/ask-the-performance-team/listener-certificate-configurations-in-windows-server-2012-2012/ba-p/375467

param($result)

Import-Module CimCmdlets

# Apply certificate
$thumbprint = $result.ManagedItem.CertificateThumbprintHash

if ([string]::IsNullOrWhiteSpace($thumbprint)) {
    throw "Certificate thumbprint was not supplied."
}

$thumbprint = ($thumbprint -replace '\s', '').ToUpperInvariant()
$rdpListenerNamespace = 'root/cimv2/TerminalServices'
$rdpListener = Get-CimInstance -Namespace $rdpListenerNamespace -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop

if (-not $rdpListener) {
    throw "RDP listener configuration was not found."
}

$null = $rdpListener | Set-CimInstance -Property @{ SSLCertificateSHA1Hash = $thumbprint } -ErrorAction Stop

