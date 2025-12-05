# Azure Managed Certificates Provider

This provider integrates with Azure App Service Managed Certificates to monitor and track certificates managed by Azure.

## Overview

Azure App Service Managed Certificates are free SSL/TLS certificates provided by Azure for custom domains in App Service. This provider allows the Certify The Web Management Hub to discover and monitor these certificates across your Azure subscriptions.

## Features

- **Auto-discovery**: Automatically discovers all Azure Managed Certificates in specified subscriptions
- **Multi-subscription support**: Query certificates across multiple Azure subscriptions
- **Resource group filtering**: Optionally limit discovery to specific resource groups
- **Flexible authentication**: Supports multiple authentication methods:
  - Service Principal (Client ID + Secret)
  - Managed Identity
  - Default Azure Credential (for local development)
- **Renewal monitoring**: Tracks certificate expiration and renewal status

## Configuration

### Configuration File

Create a JSON configuration file (e.g., `azure-managed-certs.json`) with the following structure:

```json
{
  "SubscriptionId": "your-subscription-id",
  "ResourceGroups": [
    "resource-group-1",
    "resource-group-2"
  ],
  "TenantId": "your-tenant-id",
  "ClientId": "your-client-id",
  "ClientSecret": "your-client-secret"
}
```

### Configuration Options

| Property | Required | Description |
|----------|----------|-------------|
| `SubscriptionId` | Yes | Azure Subscription ID to query |
| `ResourceGroups` | No | Array of resource group names. If omitted, all resource groups are scanned |
| `TenantId` | No* | Azure AD Tenant ID (for service principal auth) |
| `ClientId` | No* | Azure AD Application (Client) ID (for service principal auth) |
| `ClientSecret` | No* | Azure AD Client Secret (for service principal auth) |
| `ManagedIdentityClientId` | No | Client ID for managed identity authentication |

\* Required together for service principal authentication

### Authentication Methods

#### 1. Service Principal (Recommended for Production)

**Prerequisites:**
1. Create an Azure AD App Registration
2. Create a client secret for the app
3. Grant the app **Reader** role on the subscription or resource groups
4. Grant the app **Website Contributor** role if you need to manage certificates

**Configuration:**
```json
{
  "SubscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "TenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "ClientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "ClientSecret": "your-secret-here"
}
```

**Required Azure Permissions:**
- `Microsoft.Web/certificates/read`
- `Microsoft.Resources/subscriptions/resourceGroups/read`

#### 2. Managed Identity (For Azure-hosted Management Hub)

If running the Management Hub in Azure (VM, App Service, etc.):

**Configuration:**
```json
{
  "SubscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "ManagedIdentityClientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

**Azure Setup:**
1. Enable System-assigned or User-assigned Managed Identity on your Azure resource
2. Grant the managed identity **Reader** role on the subscription

#### 3. Default Azure Credential (For Development)

For local development, you can use Azure CLI or Visual Studio credentials:

**Configuration:**
```json
{
  "SubscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

**Prerequisites:**
- Install Azure CLI and run `az login`, OR
- Sign in to Visual Studio with your Azure account

### Certify The Web Configuration

1. **In the Management Hub Settings:**
   - Navigate to **Settings** ? **Certificate Managers**
   - Find **Azure Managed Certificates**
   - Set **Enabled** to `true`
   - Set **Config Path** to your JSON config file path (e.g., `C:\ProgramData\Certify\config\azure-managed-certs.json`)

2. **Save the configuration**

3. **Verify Discovery:**
   - Navigate to **Managed Certificates**
   - You should see certificates with source `Azure Managed Certificates`

## Certificate Information Captured

For each Azure Managed Certificate, the following information is tracked:

- **Certificate Name**: The Azure resource name
- **Subject/Domain**: Primary domain name
- **Alternative Names**: All SANs configured
- **Issue Date**: When the certificate was issued
- **Expiry Date**: When the certificate expires
- **Thumbprint**: Certificate thumbprint
- **Status**: Renewal status based on expiry
- **Resource Group**: Which Azure resource group contains the certificate

## Renewal Monitoring

The provider automatically monitors certificate expiration:

- **Healthy**: Certificate has >30 days until expiry
- **Warning**: Certificate expires in <30 days (Azure should auto-renew)
- **Error**: Certificate has expired or failed to renew

Azure Managed Certificates automatically renew within 45 days of expiration, so warnings indicate potential issues with the automatic renewal process.

## Troubleshooting

### Provider Not Showing Certificates

1. **Check Azure Permissions:**
   ```bash
   az role assignment list --assignee <client-id> --all
   ```
   Ensure the principal has at least `Reader` role on the subscription.

2. **Verify Configuration:**
   - Check subscription ID is correct
   - Ensure JSON is valid
   - Verify authentication credentials are correct

3. **Check Logs:**
   - Review Certify The Web logs for Azure-related errors
   - Look for authentication or permission issues

### Authentication Errors

**Service Principal:**
- Verify tenant ID, client ID, and client secret are correct
- Ensure the app registration is not expired
- Check that the client secret hasn't expired

**Managed Identity:**
- Confirm managed identity is enabled on the Azure resource
- Verify the identity has the required role assignments

### No Certificates Found

- Verify you have Azure Managed Certificates created in App Service
- Check that the resource groups are correct (if filtering)
- Ensure certificates are in the specified subscription
- Regular App Service certificates (not "Managed") won't appear

## Limitations

- **Read-Only**: This provider only monitors certificates; it cannot create or renew them
- **Azure Managed Certificates Only**: Only detects certificates created through Azure's free managed certificate feature
- **App Service Only**: Only works with App Service Managed Certificates (not Azure Key Vault, etc.)
- **No PEM Export**: Azure doesn't provide PEM export for managed certificates

## Examples

### Minimal Configuration (Single Subscription, All Resource Groups)

```json
{
  "SubscriptionId": "12345678-1234-1234-1234-123456789012",
  "TenantId": "87654321-4321-4321-4321-210987654321",
  "ClientId": "abcdef12-3456-7890-abcd-ef1234567890",
  "ClientSecret": "your-secret-here"
}
```

### Filtered Configuration (Specific Resource Groups)

```json
{
  "SubscriptionId": "12345678-1234-1234-1234-123456789012",
  "ResourceGroups": [
    "production-web-apps",
    "staging-web-apps"
  ],
  "TenantId": "87654321-4321-4321-4321-210987654321",
  "ClientId": "abcdef12-3456-7890-abcd-ef1234567890",
  "ClientSecret": "your-secret-here"
}
```

### Managed Identity Configuration

```json
{
  "SubscriptionId": "12345678-1234-1234-1234-123456789012",
  "ManagedIdentityClientId": "98765432-8765-4321-9876-543210987654"
}
```

## Security Best Practices

1. **Use Managed Identity** when running in Azure
2. **Store secrets securely**: Never commit client secrets to source control
3. **Principle of Least Privilege**: Grant only necessary permissions
4. **Rotate Secrets**: Regularly rotate client secrets (if using service principal)
5. **Protect Config Files**: Ensure config files have appropriate file system permissions
6. **Use Resource Group Filtering**: Limit scope to only necessary resource groups

## Support

For issues or questions:
- GitHub Issues: [Certify Plugins Repository](https://github.com/webprofusion/certify-plugins)
- Documentation: [Certify The Web Docs](https://docs.certifytheweb.com)

## License

This plugin is part of the Certify Plugins package and follows the same license as the main project.
