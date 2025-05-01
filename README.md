# Overview
This repo provides a PowerShell module named `EntraAutomation` to help streamline various Microsoft Entra tasks.

Each function allows use of an existing Graph API session (Connect-MgGraph) through the `UseExistingGraphSession` switch, otherwise the default is to disconnect the existing session(if present) and connect with a fresh session. The newly created session is cleared at the end of each function.

Refer to the functions and examples below for more details.  More documentation can be found within each function.

# Functions
## Add-EntraEligibleRoleAssignmentsFromCsv
Simplifies the migration of permanent active role assignments to eligible time-bound assignments using a csv file of UPNs and Entra role names.
```
$roleParams = @{
    CsvPath                         = 'C:\assignments.csv'
    StartDate                       = Get-Date '2024-01-01Z'
    EndDate                         = Get-Date '2025-01-01Z'
    Justification                   = 'New eligible assignments to replace existing perm assignments.'
    DirectoryScopeId                = '/'
    RemoveExistingActiveAssignments = $true
}

Add-EntraEligibleRoleAssignmentsFromCsv @roleParams

```

## Export-EntraRoleAssignments
This function extracts all Entra role assignments (assigned, eligible, activated eligible) and also expands the members in role assignable groups as separate assignment objects for completeness.
```
# Extract all role assignments
$RoleAssignments = Export-EntraRoleAssignments

# Get assignments for roles that contain "Global"
$RoleAssignments | Where-Object{$_.RoleName -like "Global*"} | format-table PrincipalUPN, RoleName, AssignmentType

# Get "Assigned" (permanent) role assignments
$RoleAssignments | Where-Object{$_.AssignmentType -eq "Assigned"}

# Get assignments for service principals
$RoleAssignments | Where-Object{$_.ObjectType -eq "servicePrincipal"}

# Get all role-assignable group assignments
$RoleAssignments | Where-Object{$_.ObjectType -eq "group"} | Select-Object PrincipalDisplayName, RoleName

# Get all users that have roles through a role-assignable group
$RoleAssignments | Where-Object{$_.ObjectType -eq "user" -and $null -ne $_.SourceGroupPrincipalID} |
  Select-Object PrincipalDisplayName, RoleName, SourceGroupDisplayName, SourceGroupPrincipalId

# Get all assignments for users that are synced from on-prem
$RoleAssignments | Where-Object{$_.OnPremisesSyncEnabled -eq $true}

<# Sample output object format

AssignmentId           : 7e6bc5b0-4c6a-4f41-b938-c1c2d3e4f5a6
RoleName               : Privileged Role Administrator
RoleDefinitionId       : ba92b091-5132-4d04-8d7b-8767a116988b
AssignmentType         : Eligible
IsBuiltIn              : True
MemberType             : User
SourceGroupDisplayName :
SourceGroupPrincipalId :
PrincipalId            : a1b2c3d4-5678-4e9f-a0b1-2c3d4e5f6789
PrincipalDisplayName   : Alex Wilson
PrincipalUPN           : alex.wilson@domain.com
ObjectType             : User
OnPremisesSyncEnabled  : True
UserType               : Member
DirectoryScopeId       : /
DirectoryScopeType     : Directory
DirectoryScopeName     : MSFT
StartDateTime          : 01/05/2025 12:00:00 AM
EndDateTime            : 01/05/2026 12:00:00 AM

#>
```

## Get-ConditionalAccessConfiguration
Retrieves conditional access policies and named locations in a more human readable format with lookups done on users, groups, applications, roles, locations, and anything else that by default is exported as a GUID.
```
# Get conditional access configuration
$CAConfig = Get-ConditionalAccessConfiguration

# Get policies that include all applications
$CAConfig.Policies | Where-Object { $_.IncludeApps -eq 'All' } | Select-Object DisplayName, IncludeApps

# Get policies with excluded applications that start with `Azure`
$CAConfig.Policies | Where-Object { $_.ExcludeApps.DisplayName -like "Azure*" } | Select-Object DisplayName, ExcludeApps | fl

# Get policies with excluded users, showing the policy name and the excluded users
$CAConfig.Policies | Where-Object { $null -ne $_.ExcludeUsers } | Select-Object DisplayName, ExcludeUsers | fl

# Get policies with excluded groups showing the policy name and the groups
$CAConfig.Policies | Where-Object { $null -ne $_.ExcludeGroups } | Select-Object DisplayName, ExcludeGroups

# Get policies with included groups that start with `CA*`
$CAConfig.Policies | Where-Object { $_.IncludeGroups.DisplayName -like "CA*" }

# Get all policies with excluded users that match a UPN pattern
$CAConfig.Policies | Where-Object { $_.ExcludeUsers.UserPrincipalName -like "dev*" }

# Get all policies with a role name that starts with `Global`
$CAConfig.Policies | Where-Object { $_.IncludeRoles.DisplayName -like "Global*" }

# Get all policies with excluded countries that start with `United`
$CAConfig.Policies | Where-Object { $_.ExcludeLocations.Countries.Name -like "United*" }

# View named locations with country names and ip ranges
$CAConfig.NamedLocations | fl

# Get all policies that include countries with a pattern, and display the policy name with matched countries
$countryPattern = "Al*"
$CAConfig.Policies |
Where-Object {
    $_.IncludeLocations.Countries.Name -like $countryPattern
} |
Select-Object  DisplayName,
@{ N = 'MatchedCountries'; E = {
            ( $_.IncludeLocations.Countries |
        Where-Object { $_.Name -like $countryPattern } |
        Select-Object -Expand Name -Unique
            ) -join '; '
    }
} | Format-List

# Get all policies that exclude an IP range pattern and display the policy name with the matched IP ranges
$IpPattern = "192*"
$CAConfig.Policies |
Where-Object {
    $_.ExcludeLocations.IpRanges -like $IpPattern
} |
Select-Object  DisplayName,
@{ N = 'MatchedIpRanges'; E = {
        $_.ExcludeLocations.IpRanges -like $IpPattern
    }
} | Format-List
```

## Get-InactiveEntraAccounts
Retrieves inactive Entra accounts using a sign-in activity threshold, while excluding accounts created before the threshold and skipping guests in a pending acceptance state.
```
# Get inactive guests that have not signed in during the past 90 days
$InactiveGuests = Get-InactiveEntraAccounts -DaysThreshold 90 -UserType 'Guest'

# Get inactive accounts, both members and guests, that have not signed in during the past year using certificate-based authentication
Get-InactiveEntraAccounts -DaysThreshold 365 -ClientId "<app-client-id>" -TenantId "<tenant-id>" -CertificateThumbprint "<thumbprint>"
```

## Remove-InactiveGuestsPendingAcceptance
Automatically cleans up guest accounts with a `PendingAcceptance` state within the specified threshold.
```
# Remove guests that have not accepted their invite in the past 60 days
Remove-InactiveGuestsPendingAcceptance -DaysThreshold 60

# Remove guests that have not accepted their invite in the past 90 days using certificate-based authentication
Remove-InactiveGuestsPendingAcceptance -DaysThreshold 90 -ClientId "<app-client-id>" -TenantId "<tenant-id>" -CertificateThumbprint "<thumbprint>"
```


