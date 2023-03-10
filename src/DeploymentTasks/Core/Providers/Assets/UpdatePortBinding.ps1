# - sets the associated service port ssl binding to the new cert using netsh

# For more script info see https://docs.certifytheweb.com/docs/script-hooks.html

param($result, $port, $ip, $appid)

$thumb = $result.ManagedItem.CertificateThumbprintHash

## Apply the cert to the port binding using netsh (remove and add)

# get a new guid:
if ($appid -eq $null)
{
	$appid = [guid]::NewGuid()
}

$ipport ="${ip}:${port}"

# remove the previous certificate:
& netsh http delete sslcert ipport=$ipport

# set the current certificate:
& netsh http add sslcert ipport=$ipport certhash=$thumb appid="{$appid}"