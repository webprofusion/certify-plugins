# - sets the associated service port ssl binding to the new cert using netsh

# For more script info see https://docs.certifytheweb.com/docs/script-hooks

# $ipport (e.g. 0.0.0.0:443 or [::]:443) and $appid are validated by the task before the script runs
param($result, $ipport, $appid)

$thumb = $result.ManagedItem.CertificateThumbprintHash

## Apply the cert to the port binding using netsh (remove and add)

# if the supplied appid is null, use an arbitrary default. It's purpose is to help the user identify the associated app
if ($appid -eq $null)
{
	$appid = "c0a1e5ce-c001-c0de-ba5e-000000000042"
}

# remove the previous certificate, redirect errors etc to std out:
Write-Output "Deleting Existing Binding: [netsh http delete sslcert ipport=$ipport]"
$deleteResult = & netsh http delete sslcert "ipport=$ipport" 2>&1

# set the current certificate, report errors back:
Write-Output "Adding Updated Binding: [netsh http add sslcert ipport=$ipport certhash=$thumb appid={$appid}] "
$addResult = & netsh http add sslcert "ipport=$ipport" "certhash=$thumb" "appid={$appid}" 2>&1

if ($LASTEXITCODE -ne 0 -Or $addResult -like "*Error*" -Or $addResult -like "*incorrect*") {
	Write-Error "Error attempting to add binding: ${addResult}"
} 
else 
{
	Write-Output "Info: ${addResult}"
}
