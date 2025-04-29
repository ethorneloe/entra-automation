<#
.SYNOPSIS
Purges Entra guest users with a stale pending invitation status.

.DESCRIPTION
This function connects to Microsoft Graph, retrieves all guest users in a 'PendingAcceptance' state,
and removes those whose invitations have been pending for longer than the specified threshold.
A summary of the operation, including the number of users found, deleted, and skipped, is output in JSON format.

.PARAMETER DaysThreshold
Specifies the number of days before which a pending guest invitation should be removed.
Allowed range is 30 to 180 days. Default value is 90.

.EXAMPLE
# Example 1: Interactive connection (default)
Remove-InactiveGuestsPendingAcceptance -DaysThreshold 60
Removes all guest invitations that have been pending for more than 60 days via interactive authentication.

.EXAMPLE
# Example 2: Certificate-based connection (parameter set)
Remove-InactiveGuestsPendingAcceptance `
    -ClientId "00000000-0000-0000-0000-000000000000" `
    -CertificateThumbprint "ABCDE1234567890" `
    -TenantId "11111111-1111-1111-1111-111111111111" `
    -DaysThreshold 30
Removes all guest invitations that have been pending for more than 30 days via certificate-based authentication.

.EXAMPLE
# Example 3: Use the existing Graph session, in case the user is already connected and doing other operations with the Graph API.
# Does not disconnect the session after the operation.
Remove-InactiveGuestsPendingAcceptance -UseExistingGraphSession -DaysThreshold 45

.EXAMPLE
# Example 4: Default (no parameters)
Remove-InactiveGuestsPendingAcceptance
Removes all guest invitations that have been pending for more than the default 90 days via interactive authentication.

#>
function Remove-InactiveGuestsPendingAcceptance {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param (
        # If specified, function uses certificate-based connection
        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$TenantId,

        # If set, function will skip the connect step
        [Parameter(ParameterSetName = 'Default')]
        [switch]$UseExistingGraphSession,

        # Days before an invitation is considered stale
        [Parameter(ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(30, 180)]
        [int]$DaysThreshold = 90
    )

    # --------------------------------------------------------------------------
    # 1. IMPORT REQUIRED MODULES
    # --------------------------------------------------------------------------
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop

    # --------------------------------------------------------------------------
    # 2. INITIALIZE RESULT OBJECT
    # --------------------------------------------------------------------------
    $result = [PSCustomObject]@{
        status        = ""     # Will be set to 'Success' or 'Error'
        errorMessage  = ""     # If there's an error, store the message here
        totalFound    = 0      # How many 'PendingAcceptance' guests were found
        totalRemoved  = 0      # How many guests were successfully removed
        totalSkipped  = 0      # How many guests were skipped or failed to remove
        removedUsers  = @()    # Detailed info on deleted users
        skippedUsers  = @()    # Detailed info on skipped users
        daysThreshold = $DaysThreshold
    }

    try {
        # ----------------------------------------------------------------------
        # 3. CONNECT TO MICROSOFT GRAPH (unless reusing an existing session)
        # ----------------------------------------------------------------------
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

            if ($PSCmdlet.ParameterSetName -eq 'Certificate') {
                Connect-MgGraph -ClientId $ClientId `
                    -CertificateThumbprint $CertificateThumbprint `
                    -TenantId $TenantId `
                    -NoWelcome
            }
            else {
                # Default: Interactive connection
                Connect-MgGraph -NoWelcome
            }
        }

        # ----------------------------------------------------------------------
        # 4. RETRIEVE GUEST USERS WITH STALE PENDING INVITATION STATUS
        # ----------------------------------------------------------------------
        $cutoffDate = (Get-Date).AddDays(-$DaysThreshold).ToUniversalTime()
        $cutoffDateStr = $cutoffDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $filter = "userType eq 'Guest' and externalUserState eq 'PendingAcceptance' and CreatedDateTime le $cutoffDateStr"
        $pendingGuests = Get-MgUser -Filter $filter -All -ErrorAction Stop

        # Add to the result object
        $result.totalFound = $pendingGuests.Count
        $result.status = "Success"

        # ----------------------------------------------------------------------
        # 5. REMOVE GUEST USERS
        # ----------------------------------------------------------------------
        foreach ($user in $pendingGuests) {


            if ($PSCmdlet.ShouldProcess("User '$($user.UserPrincipalName)'", "Remove user")) {
                try {
                    Remove-MgUser -UserId $user.Id -Confirm:$false
                    $result.totalRemoved++

                    $userToAdd = [PSCustomObject]@{
                        userPrincipalName = $user.UserPrincipalName
                        DisplayName       = $user.DisplayName
                        Id                = $user.Id
                        userType          = $user.UserType
                        externalUserState = $user.ExternalUserState
                        CreatedDateTime   = $inviteDate
                    }
                    $result.removedUsers += $userToAdd
                }
                catch {
                    $result.totalSkipped++

                    $userToAdd = [PSCustomObject]@{
                        userPrincipalName = $user.UserPrincipalName
                        DisplayName       = $user.DisplayName
                        Id                = $user.Id
                        userType          = $user.UserType
                        externalUserState = $user.ExternalUserState
                        CreatedDateTime   = $inviteDate
                        ErrorMessage      = $_.Exception.Message
                    }
                    $result.skippedUsers += $userToAdd
                }
            }
        }
    }
    catch {
        $result.status = "Error"
        $result.errorMessage = $_.Exception.Message
    }
    finally {
        # ----------------------------------------------------------------------
        # 6. OUTPUT RESULTS AND CLEAN UP
        # ----------------------------------------------------------------------
        $jsonOutput = $result | ConvertTo-Json -Depth 5
        Write-Output $jsonOutput

        # Only clean up if we are not using the existing session, as the user likely wants to keep the connection.
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}