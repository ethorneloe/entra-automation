# Overview
This repo provides a PowerShell module called `EntraAutomation` to help streamline Entra tasks.

# Functions
## Add-EntraEligibleRoleAssignmentsFromCsv
Simplifies the migration of permanent active role assignments to eligible time-bound assignments using a csv file of UPNs and Entra role names.

## Export-EntraRoleAssignments
This function extracts all Entra role assignments (assigned, eligible, activated eligibile) and also expands the members in role assignable groups as seperate assignment objects for completeness.

## Get-ConditionalAccessConfiguration
Retrieves condtional access policies in a more human readable form with lookups done on users, groups, applications, roles, locations, and anything else that by default is exported as a GUID.

## Get-InactiveEntraAccounts
Retrieves inactive Entra accounts using a sign-in activity threshold, while excluding accounts created before the threshold and guests in a pending acceptance state.
