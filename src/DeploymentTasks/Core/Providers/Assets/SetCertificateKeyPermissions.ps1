# This is an example script and it will be overwritten when the next update is installed. 
# To use this script copy it to another location and modify as required

# Set certificate for Web Management Service in port 8172 (Web Deploy etc)
# This script:
# - updates the read permission for the certificate private key to allow LOCAL_SERVICE (the web management service user) to read the private key
# - then sets the associated service port ssl binding to the new cert
# - then updates the registry key value used by the IIS management UI for the Web Management Service ot the matching cert thumbprint (as binary value)

# For more script info see https://docs.certifytheweb.com/docs/script-hooks.html

param($result, $account)

$thumb = $result.ManagedItem.CertificateThumbprintHash

## Update the read permission on the certificate private key to allow LOCAL_SERVICE to use the cert (and private key)

# Specify the user, the permissions and the permission type
$permission = $account,"Read","Allow"

# get the stored certificate 
$cert = Get-ChildItem -Path cert:\LocalMachine\My\$thumb

# configure file system access rule
$accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission;

# Location of the machine related keys
$keyPath = $env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\";
$keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName;
$keyFullPath = $keyPath + $keyName;

try
{
   # Get the current acl of the private key
   $acl = (Get-Item $keyFullPath).GetAccessControl('Access');
   # Add the new ace to the acl of the private key
   $acl.AddAccessRule($accessRule);

   # Write back the new acl
   Set-Acl -Path $keyFullPath -AclObject $acl;
}
catch
{
   throw $_;
}