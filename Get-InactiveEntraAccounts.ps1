<#
.SYNOPSIS
    Retrieves inactive Entra accounts based on sign-in activity thresholds.

.DESCRIPTION
    Retrieves Entra (Azure AD) user accounts that have not signed in for a specified number of days.
    The script skips recently created accounts whose age is younger than the threshold to avoid false positives.
    It also excludes accounts still in the 'PendingAcceptance' state, as these are managed by a separate automation process.

    The script evaluates three sign-in timestamps (interactive, non-interactive, and successful) to determine inactivity.
    If an account has never signed in, or its latest sign-in is older than the specified threshold, it's flagged as inactive.

.PARAMETER DaysThreshold
    The number of days since the last sign-in or account creation after which an account is considered inactive.

.PARAMETER UserType
    Specifies the type of user accounts to check:
        - 'Guest': Only external guest accounts.
        - 'Member': Only internal member accounts.
        - 'All' (default): Both guest and member accounts.

.PARAMETER ClientId
    (Certificate Authentication) Azure AD application client ID used for certificate-based authentication.

.PARAMETER TenantId
    (Certificate Authentication) The Azure AD (Entra) tenant ID.

.PARAMETER CertificateThumbprint
    (Certificate Authentication) Thumbprint of the certificate from the local certificate store.

.PARAMETER UseExistingGraphSession
    Skips authentication if there's an existing Microsoft Graph session.

.EXAMPLE
    # Retrieves all accounts (guests and members) inactive for 90 days or more
    Get-InactiveEntraAccounts -DaysThreshold 90

.EXAMPLE
    # Retrieves only guest accounts inactive for 180 days or more
    Get-InactiveEntraAccounts -DaysThreshold 180 -UserType Guest

.EXAMPLE
    # Using certificate-based authentication to retrieve accounts inactive for 365 days or more
    Get-InactiveEntraAccounts -DaysThreshold 365 -ClientId "<app-client-id>" -TenantId "<tenant-id>" -CertificateThumbprint "<thumbprint>"

.OUTPUTS
    PSCustomObject with the following properties:
        - AccountEnabled
        - CreationType
        - CreatedDateTime
        - ExternalUserState
        - UserType
        - UserPrincipalName
        - DisplayName
        - Id
        - LastInteractiveSignInDateTime
        - LastNonInteractiveSignInDateTime
        - LastSuccessfulSignInDateTime
        - LastSignInUsed
#>
function Get-InactiveEntraAccounts {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory)]
        [int]$DaysThreshold,

        [Parameter()]
        [ValidateSet('Guest', 'Member', 'All')]
        [string]$UserType = 'All',

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$UseExistingGraphSession
    )

    try {
        # Import required Graph modules
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

        # Connect to Graph if needed
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

        # Calculate cutoff in UTC
        $cutoffDate = (Get-Date).ToUniversalTime().AddDays(-$DaysThreshold)

        # Build userType filter
        switch ($UserType) {
            'All' { $filter = "userType eq 'Guest' or userType eq 'Member'" }
            default { $filter = "userType eq '$UserType'" }
        }

        # Retrieve users
        $users = Get-MgUser -Filter $filter -All -Property accountEnabled, creationType, createdDateTime, externalUserState, userType, userPrincipalName, displayName, id, signInActivity

        # Evaluate and collect stale accounts
        $results = foreach ($u in $users) {
            # Skip recent creations
            $created = [DateTime]$u.CreatedDateTime
            if ($created -gt $cutoffDate) { continue }

            # Skip pending invites. These are managed by a separate process.
            if ($u.ExternalUserState -eq 'PendingAcceptance') { continue }

            # Inspect sign‑in activity
            $sia = $u.SignInActivity
            if (-not $sia -or (-not $sia.LastSignInDateTime -and -not $sia.LastNonInteractiveSignInDateTime -and -not $sia.LastSuccessfulSignInDateTime)) {
                $interactive = $null; $nonInteractive = $null; $successful = $null; $latest = $null
            }
            else {
                $interactive = if ($sia.LastSignInDateTime) { [DateTime]$sia.LastSignInDateTime }         else { $null }
                $nonInteractive = if ($sia.LastNonInteractiveSignInDateTime) { [DateTime]$sia.LastNonInteractiveSignInDateTime } else { $null }
                $successful = if ($sia.LastSuccessfulSignInDateTime) { [DateTime]$sia.LastSuccessfulSignInDateTime }     else { $null }
                $latest = @($interactive, $nonInteractive, $successful) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
            }

            # Include if never signed in or stale
            if (-not $latest -or $latest -le $cutoffDate) {
                [PSCustomObject]@{
                    AccountEnabled                   = $u.AccountEnabled
                    CreationType                     = $u.CreationType
                    CreatedDateTime                  = $u.CreatedDateTime
                    ExternalUserState                = $u.ExternalUserState
                    UserType                         = $u.UserType
                    UserPrincipalName                = $u.UserPrincipalName
                    DisplayName                      = $u.DisplayName
                    Id                               = $u.Id
                    LastInteractiveSignInDateTime    = $interactive
                    LastNonInteractiveSignInDateTime = $nonInteractive
                    LastSuccessfulSignInDateTime     = $successful
                    LastSignInUsed                   = $latest
                }
            }
        }

        # Output sorted results
        $results | Sort-Object UserPrincipalName
    }
    catch {
        Write-Error -Message "Get-InactiveEntraAccounts failed: $_"
    }
    finally {
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
