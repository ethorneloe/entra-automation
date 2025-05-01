<#
.SYNOPSIS
Exports Entra application registrations and service principals with secrets and certificates.

.DESCRIPTION
This function connects to Microsoft Graph to retrieve all Entra application registrations and service principals (PreferredSingleSignOnMode eq 'saml').
It can check for expiring or expired secrets and certificates based on a specified threshold of days or include all credentials.

.PARAMETER DaysUntilExpiryThreshold
Specifies the number of days before expiration when a credential should be considered expiring. Default is 30 days.

.PARAMETER IncludeExpired
Optional switch parameter to include expired credentials in the output. By default, expired credentials are excluded.

.PARAMETER IncludeAllCredentials
Optional switch parameter to include all credentials regardless of their expiration dates. When set, the date filtering logic is bypassed.

.NOTES
- This script requires the Microsoft Graph PowerShell SDK to be installed.
- Appropriate permissions are required to read Azure AD applications and service principals.
- By default, the script connects interactively to Microsoft Graph unless `CertificateThumbprint`, `ClientId`, and `TenantId` are provided for app-only authentication.

.EXAMPLE
Export-ExpiringEntraIdAppCreds

Runs the function with default settings, exporting expiring credentials to 'C:\temp'.

.EXAMPLE
Get-ExpiringEntraAppCreds-IncludeExpired

Includes expired credentials in the output.

.EXAMPLE
Get-ExpiringEntraAppCreds-IncludeAllCredentials

Includes all credentials regardless of their expiration dates.

.EXAMPLE
Get-ExpiringEntraAppCreds-DaysUntilExpiryThreshold 60

Exports credentials that are expiring within the next 60 days.

#>
function Get-ExpiringEntraAppCreds {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Certificate')]
        [int]$DaysUntilExpiryThreshold = 30, # Default is 30 days

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Certificate')]
        [switch]$IncludeExpired = $false,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Certificate')]
        [switch]$IncludeAllCredentials = $false,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$UseExistingGraphSession
    )
    Try {

        # -------------------------------------------------------
        # 1. Import required modules
        # -------------------------------------------------------
        import-module Microsoft.Graph.Authentication -Force -ErrorAction Stop
        Import-Module Microsoft.Graph.Applications -Force -ErrorAction Stop

        #---------------------------------------------------------------------
        # 2. Connect to Graph if required
        #---------------------------------------------------------------------
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            switch ($PSCmdlet.ParameterSetName) {
                'Certificate' {
                    Connect-MgGraph -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -TenantId $TenantId -NoWelcome
                }
                'Default' {
                    Connect-MgGraph -Scopes 'User.Read.All', 'AuditLog.Read.All' -NoWelcome

                }
            }
        }

        # -------------------------------------------------------
        # 3. Retrieve all applications
        # -------------------------------------------------------
        $Applications = Get-MgApplication -All -Select "DisplayName,AppId,Id,PasswordCredentials,KeyCredentials" -ExpandProperty "Owners"

        # -------------------------------------------------------
        # 4. Process each application in parallel and retrieve credential details
        # -------------------------------------------------------
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


        # -------------------------------------------------------
        # 5. Retrieve all Service Principals with SAML signing certificates
        # -------------------------------------------------------
        $ServicePrincipals = Get-MgServicePrincipal -Filter "PreferredSingleSignOnMode eq 'saml'" -Select "DisplayName,AppId,Id,PasswordCredentials" -ExpandProperty "Owners"

        # -------------------------------------------------------
        # 6. Process each application in parallel and retrieve credential details
        # -------------------------------------------------------
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
        # -------------------------------------------------------
        # 7. Return combined results
        # -------------------------------------------------------
        return $results.ToArray()
    }
    catch {
        Write-Error "An unexpected error occurred: $($_.Exception.Message)"
    }
    finally {
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
