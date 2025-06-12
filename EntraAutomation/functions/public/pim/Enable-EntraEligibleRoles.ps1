<#
.SYNOPSIS
    Displays eligible PIM roles for the current user and bulk-activates the
    selected ones.
    
.DESCRIPTION
    1. Connects to Microsoft Graph (if not already connected).
    2. Lists every role for which the signed-in user is eligible.
    3. Prompts for:
         - Duration in hours
         - A single justification
         - Which roles to activate:
               • press <Enter> for all, or
               • comma-separated numbers from the menu
    4. Submits self-activation requests and prints a success/error line
       for each role.
    
.EXAMPLE
    Enable-EntraEligibleRoles

.NOTES
    This was designed for eligible roles that can be self-activated without requiring approval from other members.
#>
function Enable-EntraEligibleRoles {
    
    [CmdletBinding()]
    param()

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-module Microsoft.Graph.Identity.Governance -ErrorAction Stop
    
    # -------------------------------------------------------
    # 1 Ensure Graph connection
    # -------------------------------------------------------
    try {
        if (-not (Get-MgContext)) { Connect-MgGraph -NoWelcome }
    }
    catch { throw "Unable to connect to Microsoft Graph: $_" }
    
    # -------------------------------------------------------
    # 2 Fetch eligible roles
    # -------------------------------------------------------
    $context = Get-MgContext
    $currentId = (Get-MgUser -UserId $context.Account).Id
    $eligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
        -ExpandProperty RoleDefinition -All `
        -Filter "principalId eq '$currentId'" |
    Where-Object { $_.RoleDefinition.DisplayName }
    
    if (-not $eligible) {
        Write-Host "No eligible roles found." -ForegroundColor Yellow
        return
    }
    
    # -------------------------------------------------------
    # 3 Gather user input (duration & reason)
    # -------------------------------------------------------
    [int]$hours = 0
    do {
        $raw = Read-Host "Enter activation duration in hours (1-9)"
    } until (
        [int]::TryParse($raw.Trim(), [ref]$hours) -and
        $hours -ge 1 -and $hours -le 9 -or 
        (Write-Host "Please enter a number from 1-9." -ForegroundColor Red)
    )

    do {
        $reason = Read-Host "Enter a justification for ALL role activations"
    } until ($reason)
     
    # -------------------------------------------------------
    # 4 Display menu & capture selection
    # -------------------------------------------------------
    Write-Host "`nEligible roles:`n"
    $menu = @{}
    $i = 1
    foreach ($role in $eligible) {
        Write-Host ("[{0}] {1}" -f $i, $role.RoleDefinition.DisplayName)
        $menu[$i] = $role
        $i++
    }
    
    $prompt = "Enter numbers to activate (e.g. 1,3,7) or press <Enter> for ALL"
    $selectionRaw = Read-Host "`n$prompt"
    
    if ([string]::IsNullOrWhiteSpace($selectionRaw)) {
        $chosen = $eligible     
    }
    else {
        $numbers = $selectionRaw -split ',' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^\d+$' } |
        ForEach-Object { [int]$_ }
    
        $invalid = $numbers | Where-Object { $_ -lt 1 -or $_ -gt $menu.Count }
        if ($invalid) {
            Write-Host "Invalid menu number(s): $($invalid -join ', ')" -ForegroundColor Red
            return
        }
    
        $chosen = $numbers | ForEach-Object { $menu[$_] }
    }
    
    Write-Host "`nActivating $($chosen.Count) role(s)..." -ForegroundColor Cyan
    $durationIso = "PT${hours}H"
    
    # -------------------------------------------------------
    # 5 Activate each selected role
    # -------------------------------------------------------
    foreach ($role in $chosen) {
        $scope = if ([string]::IsNullOrEmpty($role.DirectoryScopeId)) { "/" } else { $role.DirectoryScopeId }
    
        $body = @{
            Action           = "selfActivate"
            PrincipalId      = $role.PrincipalId
            RoleDefinitionId = $role.RoleDefinitionId
            DirectoryScopeId = $scope
            Justification    = $reason
            ScheduleInfo     = @{
                StartDateTime = Get-Date
                Expiration    = @{
                    Type     = "AfterDuration"
                    Duration = $durationIso
                }
            }
        }
    
        try {
            New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $body | Out-Null
            Write-Host "  ✔ Activated: $($role.RoleDefinition.DisplayName)" -ForegroundColor Green
        }
        catch {
            Write-Host "  ✖ Failed: $($role.RoleDefinition.DisplayName) — $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host "`nDone." -ForegroundColor Cyan
}
