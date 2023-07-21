# - sets the associated service port ssl binding to the new cert using netsh

# For more script info see https://docs.certifytheweb.com/docs/script-hooks.html

param($result, $port, $ip, $appid)

$thumb = $result.ManagedItem.CertificateThumbprintHash

## Apply the cert to the port binding using netsh (remove and add)

# if the supplied appid is null, use an arbitrary default. It's purpose is to help the user identify the associated app
if ($appid -eq $null)
{
	$appid = "c0a1e5ce-c001-c0de-ba5e-000000000042"
}

$ipport ="${ip}`:${port}"

# remove the previous certificate, redirect errors etc to std out:
$deleteBindingCmd = "netsh http delete sslcert ipport=${ipport}"
Write-Output "Deleting Existing Binding: [$deleteBindingCmd]"
$deleteResult = Invoke-Expression $deleteBindingCmd

# set the current certificate, report errors back:
$addBindingCmd = "netsh http add sslcert ipport=${ipport} certhash=${thumb} appid='{$appid}'"
Write-Output "Adding Updated Binding: [$addBindingCmd] "
$addResult = Invoke-Expression $addBindingCmd 

if ($addResult -like "*Error*" -Or $addResult -like "*incorrect*") {
	Write-Error "Error attempting to add binding: ${addResult}"
} 
else 
{
	Write-Output "Info: ${addResult}"
}
