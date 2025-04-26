
<#
.SYNOPSIS
Exports Entra role assignments, including both active and eligible assignments, including expanded role-assignable group members.

.DESCRIPTION
Exports all assignments across Entra roles either active (assigned, activated from eligible) or eligible.
Group members of role-assignable groups are expanded to include individual members in the output.
Output includes role name, assignment type, built-in status, member type, principal details, directory scope details, and end date/time.

.PARAMETER UseExistingGraphSession
If specified, the function will use the existing Microsoft Graph session instead of establishing a new one.

.EXAMPLE
Export-EntraRoleAssignments -UseExistingGraphSession

.NOTES
- This function requires the Microsoft Graph PowerShell module.
- Group memberships for role-assignable groups are expanded, and their members are added to the output.
- Active assignments represent currently activated roles, while eligible assignments represent roles users can activate.
- Directory scope IDs are resolved to display names for administrative units.
- The SourceGroupDisplayName and SourceGroupPrincipalId fields are populated only for assignments where the objects are members of a role-assignable group.
- When a role assignment is for a group, the AssignmentId for each expanded group member is the ID of the group assignment.

#>
function Export-EntraRoleAssignments {
    [CmdletBinding()]
    param (
        [switch]$UseExistingGraphSession
    )

    try {

        #---------------------------------------------------------------------
        # 1. Import required modules
        #---------------------------------------------------------------------
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Groups -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop

        #---------------------------------------------------------------------
        # 2. Connect to Graph if required
        #---------------------------------------------------------------------
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Connect-MgGraph -Scopes 'RoleManagement.Read.Directory', 'Directory.Read.All'  -NoWelcome
        }

        #---------------------------------------------------------------------
        # 3. Declare and initialize lookup variables
        #---------------------------------------------------------------------
        # Retrieve the organization name once
        $orgName = Get-MgOrganization | Select-Object -ExpandProperty DisplayName

        # Build an administrative unit cache
        #    Key: administrativeUnitId, Value: displayName
        $adminUnitNameMap = @{}

        # Retrieve all role definitions once and build a lookup table
        $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
        $roleDefMap = @{}
        foreach ($rd in $roleDefinitions) {
            $roleDefMap[$rd.Id] = @{
                DisplayName = $rd.DisplayName
                IsBuiltIn   = $rd.IsBuiltIn
            }
        }

        #---------------------------------------------------------------------
        # 4. Extract role assignments
        #---------------------------------------------------------------------
        # Get active role assignments and tag them as "Active"
        $activeRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal |
        Select-Object *, @{Name = 'AssignmentCategory'; Expression = { 'Active' } }

        # Get eligible role assignments and tag them as "Eligible"
        $eligibleRoleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal |
        Select-Object *, @{Name = 'AssignmentCategory'; Expression = { 'Eligible' } }

        # Merge them all into a single collection
        $allRoleAssignments = @($activeRoleAssignments + $eligibleRoleAssignments)

        #---------------------------------------------------------------------
        # 4. Build custom objects to hold each role assignment with additional data
        #---------------------------------------------------------------------
        # Create a list to store final results
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Process all role assignments in a single loop
        foreach ($roleAssignment in $allRoleAssignments) {
            $roleDefinitionId = $roleAssignment.RoleDefinitionId
            $roleInfo = $roleDefMap[$roleDefinitionId]

            # Resolve the role name and built-in status, falling back if missing
            $roleName = $roleInfo.DisplayName
            $isBuiltIn = $roleInfo.IsBuiltIn
            if (-not $roleName) {
                try {
                    $roleInfo = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $roleDefinitionId
                    $roleName = $roleInfo.DisplayName
                    $isBuiltIn = $roleInfo.IsBuiltIn
                }
                catch {
                    Write-Warning "Failed to retrieve role definition for RoleDefinitionId '$roleDefinitionId': $($_.Exception.Message)"
                    $roleName = $roleDefinitionId
                    $isBuiltIn = $roleDefinitionId
                }
            }

            # Extract principal/scope info
            $ObjectType = $roleAssignment.Principal.AdditionalProperties['@odata.type'].split('#microsoft.graph.')[1]
            $principalDisplayName = $roleAssignment.Principal.AdditionalProperties['displayName']
            $principalUPN = $roleAssignment.Principal.AdditionalProperties['userPrincipalName']
            $principalId = $roleAssignment.Principal.Id
            $directoryScopeId = $roleAssignment.DirectoryScopeId
            $memberType = $roleAssignment.MemberType
            $endDateTime = if ($roleAssignment.EndDateTime) { $roleAssignment.EndDateTime } else { "Permanent" }
            $startDateTime = $roleAssignment.StartDateTime
            $roleAssignmentId = $roleAssignment.Id

            if ($roleAssignment.assignmentCategory -eq 'Active') {
                $assignmentType = $roleAssignment.AssignmentType
            }
            else {
                $assignmentType = $roleAssignment.assignmentCategory
            }

            # Resolve directory scope name (administrative unit or root directory)
            $directoryScopeName = $null

            if ($directoryScopeId -like "/administrativeUnits/*") {

                $directoryScopeType = "administrativeUnit"

                # Extract the ID part
                $administrativeUnitId = $directoryScopeId.Split('/')[-1]

                # Check cache first
                if ($adminUnitNameMap.ContainsKey($administrativeUnitId)) {
                    $directoryScopeName = $adminUnitNameMap[$administrativeUnitId]
                }
                else {
                    # Retrieve from Graph once and store in cache
                    try {
                        $adminUnit = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $administrativeUnitId
                        $adminUnitNameMap[$administrativeUnitId] = $adminUnit.DisplayName
                        $directoryScopeName = $adminUnit.DisplayName
                    }
                    catch {
                        Write-Warning "Failed to retrieve Administrative Unit '$administrativeUnitId': $($_.Exception.Message)"
                    }
                }
            }
            elseif ($directoryScopeId -eq "/") {
                $directoryScopeType = "Directory"
                $directoryScopeName = $orgName
            }

            # Retrieve user details
            if ($ObjectType -eq 'user') {
                $user = Get-MgUser -userid $principalId -Property OnPremisesSyncEnabled, UserType | Select-Object OnPremisesSyncEnabled, UserType
                $onPremisesSyncEnabled = $user.OnPremisesSyncEnabled
                $userType = $user.UserType
            }

            # Add the base record
            $results.Add([PSCustomObject]@{
                    AssignmentId           = $roleAssignmentId
                    RoleName               = $roleName
                    RoleDefinitionId       = $roleDefinitionId
                    AssignmentType         = $assignmentType
                    IsBuiltIn              = $isBuiltIn
                    MemberType             = $memberType
                    SourceGroupDisplayName = $null
                    SourceGroupPrincipalId = $null
                    PrincipalId            = $principalId
                    PrincipalDisplayName   = $principalDisplayName
                    PrincipalUPN           = $principalUPN
                    ObjectType             = $ObjectType
                    OnPremisesSyncEnabled  = $onPremisesSyncEnabled
                    UserType               = $userType
                    DirectoryScopeId       = $directoryScopeId
                    DirectoryScopeType     = $directoryScopeType
                    DirectoryScopeName     = $directoryScopeName
                    StartDateTime          = $startDateTime
                    EndDateTime            = $endDateTime
                })

            # If principal is a group, expand group members
            if ($ObjectType -eq 'group') {
                try {
                    $groupMembers = Get-MgGroupMember -GroupId $principalId
                    foreach ($member in $groupMembers) {
                        $groupMemberUPN = $member.AdditionalProperties['userPrincipalName']
                        $groupMemberType = $member.AdditionalProperties['@odata.type'].split('#microsoft.graph.')[1]
                        $groupMemberDisplayName = $member.AdditionalProperties['displayName']

                        $user = Get-MgUser -userid $member.Id -Property OnPremisesSyncEnabled, UserType | Select-Object OnPremisesSyncEnabled, UserType
                        $onPremisesSyncEnabled = $user.OnPremisesSyncEnabled
                        $userType = $user.UserType

                        $results.Add([PSCustomObject]@{
                                AssignmentId           = $roleAssignmentId # Note that this is the parent assignment ID belonging to the group.
                                RoleName               = $roleName
                                RoleDefinitionId       = $roleDefinitionId
                                AssignmentType         = $assignmentType
                                IsBuiltIn              = $isBuiltIn
                                MemberType             = 'GroupMember'
                                SourceGroupDisplayName = $principalDisplayName
                                SourceGroupPrincipalId = $principalId
                                PrincipalId            = $member.Id
                                PrincipalDisplayName   = $groupMemberDisplayName
                                PrincipalUPN           = $groupMemberUPN
                                ObjectType             = $groupMemberType
                                OnPremisesSyncEnabled  = $onPremisesSyncEnabled
                                UserType               = $userType
                                DirectoryScopeId       = $directoryScopeId
                                DirectoryScopeType     = $directoryScopeType
                                DirectoryScopeName     = $directoryScopeName
                                StartDateTime          = $startDateTime
                                EndDateTime            = $endDateTime
                            })
                    }
                }
                catch {
                    Write-Warning "Failed to get group members for GroupId '$principalId': $($_.Exception.Message)"
                }
            }
        }

        # Return an array (pipeline-friendly)
        return $results.ToArray()
    }
    catch {
        Write-Error -Message "Export-EntraRoleAssignments failed: $_"
    }
    finally {
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
