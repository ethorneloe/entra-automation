<#
.SYNOPSIS
Exports Azure AD (Entra ID) application registrations and service principals with secrets and certificates to a CSV file or database.

.DESCRIPTION
This function connects to Microsoft Graph to retrieve all Entra ID application registrations and service principals (PreferredSingleSignOnMode eq 'saml').
It can check for expiring or expired secrets and certificates based on a specified threshold of days or include all credentials.
It exports the details to a CSV file at the specified path or inserts them into a SQL database table, depending on the chosen parameter set.
The function supports both interactive authentication and app-only authentication using a certificate.

.PARAMETER DaysUntilExpiryThreshold
Specifies the number of days before expiration when a credential should be considered expiring. Default is 30 days.

.PARAMETER IncludeExpired
Optional switch parameter to include expired credentials in the output. By default, expired credentials are excluded.

.PARAMETER IncludeAllCredentials
Optional switch parameter to include all credentials regardless of their expiration dates. When set, the date filtering logic is bypassed.

.PARAMETER CsvExportPath
Specifies the path where the CSV file will be exported when using the 'Csv' parameter set. Default is 'C:\temp'.

.PARAMETER SQLServerInstance
Specifies the SQL Server instance when using the 'Database' parameter set.

.PARAMETER SQLDatabase
Specifies the SQL database name when using the 'Database' parameter set.

.PARAMETER SQLTable
Specifies the SQL table name where the data will be inserted when using the 'Database' parameter set.

.PARAMETER ClearSQLTable
A switch for clearing the SQL table the data is exported to.

.PARAMETER CertificateThumbprint
(Optional) The thumbprint of the certificate to use for app-only authentication when connecting to Microsoft Graph.

.PARAMETER ClientId
(Optional) The client ID (application ID) to use for authentication when connecting to Microsoft Graph.

.PARAMETER TenantId
(Optional) The tenant ID to use for authentication when connecting to Microsoft Graph.

.NOTES
- This script requires the Microsoft Graph PowerShell SDK to be installed.
- Appropriate permissions are required to read Azure AD applications and service principals.
- By default, the script connects interactively to Microsoft Graph unless `CertificateThumbprint`, `ClientId`, and `TenantId` are provided for app-only authentication.

.EXAMPLE
Export-ExpiringEntraIdAppCreds

Runs the function with default settings, exporting expiring credentials to 'C:\temp'.

.EXAMPLE
Export-ExpiringEntraIdAppCreds -IncludeExpired

Includes expired credentials in the output.

.EXAMPLE
Export-ExpiringEntraIdAppCreds -IncludeAllCredentials

Includes all credentials regardless of their expiration dates.

.EXAMPLE
Export-ExpiringEntraIdAppCreds -DaysUntilExpiryThreshold 60 -CsvExportPath 'C:\Exports'

Exports credentials that are expiring within the next 60 days to the specified CSV export path.

.EXAMPLE
$Params = @{
    DaysUntilExpiryThreshold = 30
    IncludeExpired           = $true
    SQLServerInstance        = 'YourSQLServerInstance'
    SQLDatabase              = 'YourDatabaseName'
    SQLTable                 = 'YourTableName'
}
Export-ExpiringEntraIdAppCreds @Params -ParameterSetName 'Database'

Exports expiring credentials to a SQL database table using the 'Database' parameter set.

.EXAMPLE
Export-ExpiringEntraIdAppCreds -CertificateThumbprint 'ABCDEF1234567890' -ClientId 'your-client-id' -TenantId 'your-tenant-id' -IncludeAllCredentials

Runs the function using app-only authentication with a certificate and includes all credentials.

#>
function Export-ExpiringEntraIdAppCreds {
    [CmdletBinding(DefaultParameterSetName = 'Csv')]
    param (
        [int]$DaysUntilExpiryThreshold = 30, # Default is 30 days

        [switch]$IncludeExpired = $false,

        [switch]$IncludeAllCredentials = $false,

        [string]$CertificateThumbprint,

        [string]$ClientId,

        [string]$TenantId
    )

    Import-Module Microsoft.Graph.Authentication -Force -ErrorAction Stop
    Import-Module Microsoft.Graph.Applications -Force -ErrorAction Stop

    # Remove existing session
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Try {
        if ((-not $CertificateThumbprint) -and (-not $ClientId) -and (-not $TenantId)) {
            Connect-MgGraph -NoWelcome
        }
        else {
            Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientId -TenantId $TenantId -NoWelcome
        }
    }
    catch {
        throw ("Unable to connect to Graph API. Error: " + $_.Exception.Message)
    }

    # Retrieve all applications
    $Applications = Get-MgApplication -All -Select "DisplayName,AppId,Id,PasswordCredentials,KeyCredentials" -ExpandProperty "Owners"

    # Create a thread-safe concurrent bag to store results
    $results = [System.Collections.Concurrent.ConcurrentBag[pscustomobject]]::new()

    $Applications | ForEach-Object -Parallel {

        $_results = $using:results
        $_DaysUntilExpiryThreshold = $using:DaysUntilExpiryThreshold
        $_IncludeExpired = $using:IncludeExpired.IsPresent
        $_IncludeAllCredentials = $using:IncludeAllCredentials.IsPresent
        $Today = Get-Date -AsUTC

        $App = $_
        $AppName = $App.DisplayName
        $ObjectId = $App.Id
        $AppId = $App.AppId

        $Secrets = $App.PasswordCredentials
        $Certs = $App.KeyCredentials

        $Owners = $App.Owners
        $OwnerUPNs = $Owners.AdditionalProperties.userPrincipalName -join '|'
        $OwnerIDs = $Owners.Id -join '|'
        $OwnerEmails = $Owners.AdditionalProperties.mail -join '|'

        foreach ($Secret in $Secrets) {

            $EndDate = $Secret.EndDateTime
            $StartDate = $Secret.StartDateTime
            $DaysLeft = ($EndDate - $Today).Days
            $SecretName = $Secret.DisplayName

            if ($_IncludeAllCredentials -or ($DaysLeft -le $_DaysUntilExpiryThreshold)) {

                # Skip expired secrets if IncludeExpired is set to false
                if (-not $_IncludeAllCredentials) {
                    if ($_IncludeExpired -eq $false -and $DaysLeft -lt 0) {
                        continue
                    }
                }

                $AppDetails = [PSCustomObject]@{
                    'EntraObjectType' = 'App Registration'
                    'CredentialType'  = 'Secret'
                    'AppName'         = $AppName
                    'AppId'           = $AppId
                    'ObjectId'        = $ObjectId
                    'CredId'          = $Secret.KeyId
                    'CredName'        = $SecretName
                    'CredStartDate'   = $StartDate
                    'CredEndDate'     = $EndDate
                    'OwnerIDs'        = $OwnerIDs
                    'OwnerUPNs'       = $OwnerUPNs
                    'OwnerEmails'     = $OwnerEmails
                }

                $_results.add($AppDetails)
            }
        }

        foreach ($Cert in $Certs) {

            $EndDate = $Cert.EndDateTime
            $StartDate = $Cert.StartDateTime
            $DaysLeft = ($EndDate - $Today).Days
            $CertName = $Cert.DisplayName

            if ($_IncludeAllCredentials -or ($DaysLeft -le $_DaysUntilExpiryThreshold)) {

                # Skip expired certificates if IncludeExpired is set to false
                if (-not $_IncludeAllCredentials) {
                    if ($_IncludeExpired -eq $false -and $DaysLeft -lt 0) {
                        continue
                    }
                }

                $AppDetails = [PSCustomObject]@{
                    'EntraObjectType' = 'App Registration'
                    'CredentialType'  = 'Certificate'
                    'AppName'         = $AppName
                    'AppId'           = $AppId
                    'ObjectId'        = $ObjectId
                    'CredId'          = $Cert.KeyId
                    'CredName'        = $CertName
                    'CredStartDate'   = $StartDate
                    'CredEndDate'     = $EndDate
                    'OwnerIDs'        = $OwnerIDs
                    'OwnerUPNs'       = $OwnerUPNs
                    'OwnerEmails'     = $OwnerEmails
                }

                $_results.add($AppDetails)
            }
        }
    }

    # Check SAML Signing Certificates on SPs with PreferredSingleSignOnMode set to 'saml'
    $ServicePrincipals = Get-MgServicePrincipal -Filter "PreferredSingleSignOnMode eq 'saml'" -Select "DisplayName,AppId,Id,PasswordCredentials" -ExpandProperty "Owners"

    $ServicePrincipals | ForEach-Object -Parallel {

        $_results = $using:results
        $_DaysUntilExpiryThreshold = $using:DaysUntilExpiryThreshold
        $_IncludeExpired = $using:IncludeExpired.IsPresent
        $_IncludeAllCredentials = $using:IncludeAllCredentials.IsPresent
        $Today = Get-Date -AsUTC

        $SP = $_
        $AppName = $SP.DisplayName
        $ObjectId = $SP.Id
        $AppId = $SP.AppId

        $SamlCerts = $SP.PasswordCredentials

        $Owners = $SP.Owners
        $OwnerUPNs = $Owners.AdditionalProperties.userPrincipalName -join '|'
        $OwnerIDs = $Owners.Id -join '|'
        $OwnerEmails = $Owners.AdditionalProperties.mail -join '|'

        foreach ($Cert in $SamlCerts) {

            $EndDate = $Cert.EndDateTime
            $StartDate = $Cert.StartDateTime
            $DaysLeft = ($EndDate - $Today).Days
            $CertName = $Cert.DisplayName

            if ($_IncludeAllCredentials -or ($DaysLeft -le $_DaysUntilExpiryThreshold)) {

                # Skip expired certificates if IncludeExpired is set to false
                if (-not $_IncludeAllCredentials) {
                    if ($_IncludeExpired -eq $false -and $DaysLeft -lt 0) {
                        continue
                    }
                }

                $AppDetails = [PSCustomObject]@{
                    'EntraObjectType' = 'Service Principal'
                    'CredentialType'  = 'SAML Signing Certificate'
                    'AppName'         = $AppName
                    'AppId'           = $AppId
                    'ObjectId'        = $ObjectId
                    'CredId'          = $Cert.KeyId
                    'CredName'        = $CertName
                    'CredStartDate'   = $StartDate
                    'CredEndDate'     = $EndDate
                    'OwnerIDs'        = $OwnerIDs
                    'OwnerUPNs'       = $OwnerUPNs
                    'OwnerEmails'     = $OwnerEmails
                }

                $_results.add($AppDetails)
            }
        }
    }
    return $results.ToArray()
}
