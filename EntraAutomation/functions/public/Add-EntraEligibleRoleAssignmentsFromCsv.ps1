<#
.SYNOPSIS
Assigns eligible Azure AD (Entra) role assignments from a CSV containing UPN and RoleName.

.DESCRIPTION
Add-EntraEligibleRoleAssignmentsFromCsv reads from a CSV file (containing columns UPN and RoleName),
verifies that each user exists in Azure AD, and that each role name matches a valid Directory Role definition.
Afterward, it checks if an eligibility schedule for that (user, role, scope) already exists. If not, it creates
a new role eligibility schedule request.

.PARAMETER CsvPath
Specifies the path to the CSV file containing columns: UPN, RoleName.

.PARAMETER StartDate
Specifies the start date/time of the eligible assignment.

.PARAMETER EndDate
Specifies the end date/time of the eligible assignment.

.PARAMETER Justification
Provides a justification string for the eligibility assignment request.

.PARAMETER DirectoryScopeId
Specifies the scope at which the role is assigned. Defaults to "/".

.PARAMETER RemoveExistingActiveAssignments
When specified, remove any existing *active* assignment schedules for this (principal, role, scope)
before creating the new eligibility assignment.

.EXAMPLE
Add-EntraEligibleRoleAssignmentsFromCsv -CsvPath "C:\assignments.csv" -StartDate (Get-Date "2024-01-01Z") `
  -EndDate (Get-Date "2025-01-01Z") -Justification "Quarterly rollout" -DirectoryScopeId "/" -RemoveExistingActiveAssignments

In this example, the function reads 'assignments.csv', ensures roles and users exist, then removes
any active assignments at the same scope if present, and finally creates an eligible assignment for each record.
#>

.NOTES
# Make sure to connect with an account that has the necessary permissions to manage role assignments in Entra.
function Add-EntraEligibleRoleAssignmentsFromCsv {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CsvPath,

        [Parameter(Mandatory)]
        [datetime]$StartDate,

        [Parameter(Mandatory)]
        [datetime]$EndDate,

        [Parameter(Mandatory)]
        [string]$Justification,

        [string]$DirectoryScopeId = "/",

        [switch]$RemoveExistingActiveAssignments = $false,

        [switch]$UseExistingGraphSession
    )

    try {

        # -------------------------------------------------------
        # 1. Import the required modules
        # -------------------------------------------------------
        Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop

        # -------------------------------------------------------
        # 2. Connect to Graph if not using an existing session
        # -------------------------------------------------------
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Connect-MgGraph -Scopes 'RoleManagement.ReadWrite.Directory' -NoWelcome
        }

        # -------------------------------------------------------
        # 3. Retrieve all Role Definitions
        # -------------------------------------------------------
        try {
            $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
            Write-Output "Successfully retrieved role definitions"
        }
        catch {
            Write-Error "Failed to retrieve role definitions"
            Write-Error $_.Exception.Message
            return
        }

        # Build a hashtable keyed by DisplayName -> ID
        $roleDefByNameMap = @{}
        foreach ($rd in $roleDefinitions) {
            $roleDefByNameMap[$rd.DisplayName] = $rd.Id
        }

        # -------------------------------------------------------
        # 4. Import CSV and gather unique roles and UPNs
        # -------------------------------------------------------
        try {
            # Import the CSV, then Trim() RoleName and UPN in a pipeline
            $assignments = Import-Csv -Path $CsvPath |
            ForEach-Object {
                $_.RoleName = $_.RoleName.Trim()
                $_.UPN = $_.UPN.Trim()
                $_
            } |
            Sort-Object -Property RoleName, UPN -Descending

            Write-Output "Successfully imported CSV: $CsvPath"
        }
        catch {
            Write-Error "Failed to import CSV: $CsvPath"
            Write-Error $_.Exception.Message
            return
        }

        $uniqueRoles = $assignments | Select-Object -ExpandProperty RoleName -Unique
        $uniqueUpns = $assignments | Select-Object -ExpandProperty UPN -Unique

        # -------------------------------------------------------
        # 5. Validate that all roles in CSV exist
        # -------------------------------------------------------
        $missingRoles = $uniqueRoles | Where-Object { -not $roleDefByNameMap.ContainsKey($_) }

        # -------------------------------------------------------
        # 6. Validate all users in CSV exist
        # -------------------------------------------------------
        $validUsersMap = @{}   # upn => user object
        $missingUsers = @()

        foreach ($upn in $uniqueUpns) {
            $trimmedUpn = $upn.Trim()
            try {
                # Using -UserId because you can pass the UPN directly
                $user = Get-MgUser -UserId $trimmedUpn -ErrorAction Stop
                if ($user) {
                    # Store the user object keyed by the lowercased UPN
                    $validUsersMap[$trimmedUpn.ToLower()] = $user
                }
                else {
                    $missingUsers += $trimmedUpn
                }
            }
            catch {
                $missingUsers += $trimmedUpn
            }
        }

        if ($missingRoles -or $missingUsers) {
            if ($missingRoles) {
                Write-Warning "The following roles were not found:"
                $missingRoles | ForEach-Object { Write-Warning "    $_" }
                # If desired, you could 'return' here to block processing.
            }

            if ($missingUsers) {
                Write-Warning "The following UPNs were not found:"
                $missingUsers | ForEach-Object { Write-Warning "    $_" }
            }
            return
        }

        # -------------------------------------------------------
        # 7. Process assignments
        # -------------------------------------------------------
        Write-Output "Starting assignment loop..."
        foreach ($assignment in $assignments) {

            $roleName = $assignment.RoleName
            $upn = $assignment.UPN

            # Retrieve roleDefinitionId and principalId
            $roleDefinitionId = $roleDefByNameMap[$roleName]
            $principalId = $validUsersMap[$upn.ToLower()].Id

            # -------------------------------------------------------
            # Check for existing permanently active assignment(s)
            # -------------------------------------------------------
            $activeFilter = "principalId eq '$($principalId)' and roleDefinitionId eq '$($roleDefinitionId)' and directoryScopeId eq '$($DirectoryScopeId)'"
            try {
                $existingAssignedRoles = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance `
                    -Filter $activeFilter -All
            }
            catch {
                Write-Output "$roleName, $upn, Error, Failed To Check Existing Assignments: $($_.Exception.Message)"
                continue
            }

            # If we have existing active assignments, optionally remove them:
            if ($existingAssignedRoles) {
                if ($RemoveExistingActiveAssignments) {
                    foreach ($instance in $existingAssignedRoles) {
                        try {
                            Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $instance.Id -ErrorAction Stop
                            Write-Output "$roleName, $upn, Success, Removed Existing Active Assignment (Id: $($instance.Id))"
                        }
                        catch {
                            Write-Output "$roleName, $upn, Error, Failed To Remove Existing Active Assignment (Id: $($instance.Id)): $($_.Exception.Message)"
                        }
                    }
                }
                else {
                    Write-Output "$roleName, $upn, Skipped, 'Skipping Removal of Existing Permanently Active Assignment(s)'"
                }
            }

            # -------------------------------------------------------
            # 8. Check if there's already an eligibility schedule
            # -------------------------------------------------------
            $eligibilityFilter = "principalId eq '$($principalId)' and roleDefinitionId eq '$($roleDefinitionId)' and directoryScopeId eq '$($DirectoryScopeId)'"
            try {
                $existingEligibility = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
                    -Filter $eligibilityFilter -All
            }
            catch {
                Write-Output "$roleName, $upn, Error, FailedToCheckExisting: $($_.Exception.Message)"
                continue
            }

            if ($existingEligibility) {
                Write-Output "$roleName, $upn, Skipped, 'Eligibility Schedule Exists'"
                continue
            }

            # -------------------------------------------------------
            # 9. Build the eligibility request
            # -------------------------------------------------------
            $params = @{
                action           = "adminAssign"
                justification    = $Justification
                roleDefinitionId = $roleDefinitionId
                directoryScopeId = $DirectoryScopeId
                principalId      = $principalId
                scheduleInfo     = @{
                    startDateTime = $StartDate
                    expiration    = @{
                        type        = "afterDateTime"
                        endDateTime = $EndDate
                    }
                }
            }

            # -------------------------------------------------------
            # 10. Create the eligibility schedule
            # -------------------------------------------------------
            try {
                $result = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
                Write-Output "$roleName, $upn, Success, $($result.Status)"
            }
            catch {
                Write-Output "$roleName, $upn, Error, $($_.Exception.Message)"
            }
        }

        Write-Output "All CSV rows processed."
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
