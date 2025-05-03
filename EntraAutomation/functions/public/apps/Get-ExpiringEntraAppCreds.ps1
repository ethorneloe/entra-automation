<#
.SYNOPSIS
    Retrieves all Entra application registrations and service principals, and identifies credentials approaching or past expiration.

.DESCRIPTION
    Connects to Microsoft Graph and fetches:
      - All application registrations
      - All service principals (filtering on PreferredSingleSignOnMode = 'saml')

    For each object, the function examines password secrets and certificate credentials, and:
      - Flags those expiring within a user-defined threshold
      - Optionally includes already expired credentials
      - Optionally bypasses expiry filtering to return every credential

.PARAMETER DaysUntilExpiryThreshold
    The number of days from today within which a credential is considered “expiring.”
    Defaults to 30 days.

.PARAMETER IncludeExpired
    When specified, expired credentials (EndDateTime &lt; today) are included in the results.
    By default, expired entries are excluded.

.PARAMETER IncludeAllCredentials
    When specified, returns every secret and certificate, regardless of expiration date,
    effectively disabling any filtering based on DaysUntilExpiryThreshold or IncludeExpired.

.PARAMETER UseExistingGraphSession
    When specified, reuses an existing Microsoft Graph connection instead of initiating a new interactive or certificate-based login.

.PARAMETER ClientId
    The application (client) ID used for certificate-based (app-only) authentication.
    Required when CertificateThumbprint and TenantId are provided.

.PARAMETER TenantId
    The Azure AD tenant ID for certificate-based authentication.
    Required when CertificateThumbprint and ClientId are provided.

.PARAMETER CertificateThumbprint
    Thumbprint of the local certificate used to authenticate as an app.
    Required when ClientId and TenantId are provided.

.NOTES
    - Requires the Microsoft.Graph PowerShell SDK modules:
        Microsoft.Graph.Authentication
        Microsoft.Graph.Applications
        Microsoft.Graph.ServicePrincipals
    - The calling identity must have Application.Read.All and Directory.Read.All (or equivalent) permissions.
    - By default, connects interactively. Supply ClientId, TenantId, and CertificateThumbprint for app-only auth.

.EXAMPLE
    Get-ExpiringEntraAppCreds

    Runs with default settings (30-day threshold), omitting already expired credentials.

.EXAMPLE
    Get-ExpiringEntraAppCreds -IncludeExpired

    Includes both expiring and already expired credentials in the output.

.EXAMPLE
    Get-ExpiringEntraAppCreds -IncludeAllCredentials

    Returns every secret and certificate, ignoring any expiry filters.

.EXAMPLE
    Get-ExpiringEntraAppCreds -DaysUntilExpiryThreshold 60

    Flags credentials expiring within the next 60 days.
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
