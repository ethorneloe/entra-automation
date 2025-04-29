<#
.SYNOPSIS
Return every Conditional Access policy that has one or more
excluded groups.

.PARAMETER Config
The object produced by Get-CAPolicyConfiguration. Accepts pipeline input.

.EXAMPLE
$cfg | Get-CAPoliciesWithExcludedGroups
#>
function Get-CAPoliciesWithExcludedGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject]$Config
    )

    process {
        $Config.Policies |
        Where-Object { @($_.ExcludeGroups).Count -gt 0 } |
        Select-Object PolicyId, DisplayName, State,
        @{N = 'ExcludedGroups'; E = { ($_.ExcludeGroups.DisplayName) } }
    }
}
