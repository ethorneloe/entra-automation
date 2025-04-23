<#
.SYNOPSIS
    Retrieve Conditional Access policies, named locations, and Terms of Use agreements as PowerShell objects.
.DESCRIPTION
    Connects to Microsoft Graph to fetch all Conditional Access policies, named locations, and Terms of Use agreements.
    Resolves GUIDs for users, groups, applications, roles, locations, and ToU policies into human-readable names using in-memory caches.
    Supports interactive, certificate-based, system-assigned MI, or user-assigned MI authentication, and can reuse an existing Graph session.
    Returns a single object containing 'Policies', 'NamedLocations', and 'TermsOfUseAgreements'.
.PARAMETER ClientId
    The App (client) ID for certificate-based authentication.
.PARAMETER CertificateThumbprint
    The certificate thumbprint in the local machine or user store for certificate auth.
.PARAMETER TenantId
    Tenant ID for certificate auth.
.PARAMETER UseSystemMI
    When specified, uses the system-assigned Managed Identity.
.PARAMETER UserMIClientId
    Client ID of a user-assigned Managed Identity.
.PARAMETER UseExistingGraphSession
    Skip creating a new Graph session if set.
.EXAMPLE
    # Interactive connection
    Get-ConditionalAccessConfiguration
.EXAMPLE
    # Certificate-based
    Get-ConditionalAccessConfiguration -ClientId <appId> -CertificateThumbprint <thumb> -TenantId <tenantId>
.EXAMPLE
    # System-assigned MI
    Get-ConditionalAccessConfiguration -UseSystemMI
.EXAMPLE
    # User-assigned MI
    Get-ConditionalAccessConfiguration -UserMIClientId <identityClientId>
.EXAMPLE
    # Reuse session
    Get-ConditionalAccessConfiguration -UseExistingGraphSession
#>
function Get-ConditionalAccessConfiguration {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$ClientId,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Certificate', Mandatory = $true)]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'SystemMI', Mandatory = $true)]
        [switch]$UseSystemMI,

        [Parameter(ParameterSetName = 'UserMI', Mandatory = $true)]
        [string]$UserMIClientId,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$UseExistingGraphSession
    )

    try {
        #---------------------------------------------------------------------
        # 1. Import required modules
        #---------------------------------------------------------------------
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        Import-Module Microsoft.Graph.Groups -ErrorAction Stop

        #---------------------------------------------------------------------
        # 2. Connect to Microsoft Graph
        #---------------------------------------------------------------------
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            switch ($PSCmdlet.ParameterSetName) {

                'Certificate' {
                    Connect-MgGraph `
                        -ClientId $ClientId `
                        -CertificateThumbprint $CertificateThumbprint `
                        -TenantId $TenantId `
                        -NoWelcome
                }

                'SystemMI' {
                    Connect-MgGraph `
                        -Identity `
                        -NoWelcome
                }

                'UserMI' {
                    Connect-MgGraph `
                        -Identity `
                        -ClientId $UserMIClientId `
                        -NoWelcome
                }

                'Default' {
                    Connect-MgGraph `
                        -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Agreement.Read.All' `
                        -NoWelcome
                }
            }
        }

        #---------------------------------------------------------------------
        # 3. Fetch data
        #---------------------------------------------------------------------
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        $namedLocs = @(Get-MgIdentityConditionalAccessNamedLocation -All)
        $touAgreements = @(Get-MgIdentityGovernanceTermsOfUseAgreement -All)

        #---------------------------------------------------------------------
        # 4. Initialize caches
        #---------------------------------------------------------------------
        $userCache = @{}
        $groupCache = @{}
        $appCache = @{}
        $roleCache = @{}
        $nlCache = @{}
        $touCache = @{}

        foreach ($nl in $namedLocs) {
            $nlCache[$nl.Id] = $nl.DisplayName
        }
        foreach ($tou in $touAgreements) {
            $touCache[$tou.Id] = $tou.DisplayName
        }

        #---------------------------------------------------------------------
        # 5. Resolver function for IDs and tokens
        #---------------------------------------------------------------------
        function Resolve-Entity {
            param(
                [string]$Id,
                [ValidateSet('User', 'Group', 'App', 'Role', 'Location', 'TermsOfUse')] [string]$Type
            )

            if (-not $Id) {
                return $null
            }

            switch ($Id) {
                'All' { return 'All' }
                'None' { return 'None' }
                'GuestsOrExternalUsers' { return 'GuestsOrExternalUsers' }
                'AllTrusted' { return 'AllTrusted' }
                'Office365' { 'Office365' }
            }

            switch ($Type) {
                'User' {
                    if (-not $userCache.ContainsKey($Id)) {
                        $u = Get-MgUser -UserId $Id -ErrorAction SilentlyContinue
                        $userCache[$Id] = if ($u) { $u.UserPrincipalName } else { "UnknownUser($Id)" }
                    }
                    return $userCache[$Id]
                }

                'Group' {
                    if (-not $groupCache.ContainsKey($Id)) {
                        $g = Get-MgGroup -GroupId $Id -ErrorAction SilentlyContinue
                        $groupCache[$Id] = if ($g) { $g.DisplayName } else { "UnknownGroup($Id)" }
                    }
                    return $groupCache[$Id]
                }

                'App' {
                    if (-not $appCache.ContainsKey($Id)) {
                        $sp = Get-MgServicePrincipal -Filter "appId eq '$Id'" -ErrorAction SilentlyContinue
                        $appCache[$Id] = if ($sp) { $sp.DisplayName } else { "UnknownApp($Id)" }
                    }
                    return $appCache[$Id]
                }

                'Role' {
                    if (-not $roleCache.ContainsKey($Id)) {
                        $rt = Get-MgDirectoryRoleTemplate -Filter "id eq '$Id'" -ErrorAction SilentlyContinue
                        $roleCache[$Id] = if ($rt) { $rt.DisplayName } else { "UnknownRole($Id)" }
                    }
                    return $roleCache[$Id]
                }

                'Location' {
                    return $nlCache[$Id]
                }

                'TermsOfUse' {
                    return $touCache[$Id] -or "UnknownToU($Id)"
                }
            }
        }

        #---------------------------------------------------------------------
        # 6. Build policy objects
        #---------------------------------------------------------------------
        # Helper for safe nested property access (PS5‑compatible)
        function Get-SafeValue {
            param($Expression, $Default = $null)
            try { & $Expression } catch { $Default }
        }

        # ------------------------------------------------------------------
        # Build policy objects
        # ------------------------------------------------------------------
        Write-Verbose 'Building policy objects…'
        $policyObjects = $policies | ForEach-Object {
            $p = $_
            [PSCustomObject]@{
                DisplayName             = $p.DisplayName
                PolicyId                = $p.Id
                State                   = $p.State
                Created                 = $p.CreatedDateTime
                Modified                = $p.ModifiedDateTime

                # ----- Users / groups / roles --------------------------------------------------
                IncludeUsers            = $p.Conditions.Users.IncludeUsers    | ForEach-Object { Resolve-Entity $_ 'User' }
                ExcludeUsers            = $p.Conditions.Users.ExcludeUsers    | ForEach-Object { Resolve-Entity $_ 'User' }
                IncludeGroups           = $p.Conditions.Users.IncludeGroups   | ForEach-Object { Resolve-Entity $_ 'Group' }
                ExcludeGroups           = $p.Conditions.Users.ExcludeGroups   | ForEach-Object { Resolve-Entity $_ 'Group' }
                IncludeRoles            = $p.Conditions.Users.IncludeRoles    | ForEach-Object { Resolve-Entity $_ 'Role' }
                ExcludeRoles            = $p.Conditions.Users.ExcludeRoles    | ForEach-Object { Resolve-Entity $_ 'Role' }

                # ----- Applications ------------------------------------------------------------
                IncludeApps             = $p.Conditions.Applications.IncludeApplications | ForEach-Object { Resolve-Entity $_ 'App' }
                ExcludeApps             = $p.Conditions.Applications.ExcludeApplications | ForEach-Object { Resolve-Entity $_ 'App' }
                IncludeUserActions      = $p.Conditions.Applications.IncludeUserActions

                # ----- Locations ---------------------------------------------------------------
                IncludeLocations        = $p.Conditions.Locations.IncludeLocations | ForEach-Object { Resolve-Entity $_ 'Location' }
                ExcludeLocations        = $p.Conditions.Locations.ExcludeLocations | ForEach-Object { Resolve-Entity $_ 'Location' }

                # ----- Risk / platform / device -----------------------------------------------
                UserRiskLevels          = @($p.Conditions.UserRiskLevels)
                SignInRiskLevels        = @($p.Conditions.SignInRiskLevels)
                InsiderRiskLevels       = @($p.Conditions.Users.InsiderRiskLevels)
                ClientAppTypes          = @($p.Conditions.ClientAppTypes)
                IncludePlatforms        = @($p.Conditions.Platforms.IncludePlatforms)
                ExcludePlatforms        = @($p.Conditions.Platforms.ExcludePlatforms)

                DeviceFilterMode        = Get-SafeValue { $p.Conditions.Devices.DeviceFilter.Mode }
                DeviceFilterRule        = Get-SafeValue { $p.Conditions.Devices.DeviceFilter.Rule }

                # ----- Grant controls ----------------------------------------------------------
                GrantControls           = @($p.GrantControls.BuiltInControls)
                CustomAuthFactors       = @($p.GrantControls.CustomAuthenticationFactors)
                TermsOfUse              = $p.GrantControls.TermsOfUse | ForEach-Object { Resolve-Entity $_ 'TermsOfUse' }
                Operator                = $p.GrantControls.Operator
                AuthenticationStrength  = if ($p.GrantControls.AuthenticationStrength) {
                    [PSCustomObject]@{
                        AuthenticationStrengthId = $p.GrantControls.AuthenticationStrength.Id
                        DisplayName              = $p.GrantControls.AuthenticationStrength.DisplayName
                        PolicyType               = $p.GrantControls.AuthenticationStrength.PolicyType
                        AllowedCombinations      = $p.GrantControls.AuthenticationStrength.AllowedCombinations
                        RequirementsSatisfied    = $p.GrantControls.AuthenticationStrength.RequirementsSatisfied
                    }
                }

                # ----- Session controls --------------------------------------------------------
                CloudAppSecType         = Get-SafeValue { $p.SessionControls.CloudAppSecurity.CloudAppSecurityType }
                AppEnforcedRestrictions = Get-SafeValue { $p.SessionControls.ApplicationEnforcedRestrictions.IsEnabled }
                PersistentBrowser       = Get-SafeValue { $p.SessionControls.PersistentBrowser.IsEnabled }
                TokenProtectionType     = Get-SafeValue { $p.SessionControls.TokenProtection.TokenProtectionType }
                SignInFrequency         = if (Get-SafeValue { $p.SessionControls.SignInFrequency.IsEnabled }) {
                    [PSCustomObject]@{
                        Value = $p.SessionControls.SignInFrequency.Value
                        Type  = $p.SessionControls.SignInFrequency.Type
                    }
                }
            }
        }

        #---------------------------------------------------------------------
        # 7. Build named location objects with IP ranges and Geo details
        #---------------------------------------------------------------------
        $namedLocationObjects = $namedLocs | ForEach-Object {
            [PSCustomObject]@{
                Id                                = $_.Id
                DisplayName                       = $_.DisplayName
                IsTrusted                         = if ($_.AdditionalProperties.isTrusted) { $true } else { $false }
                IpRanges                          = @($_.AdditionalProperties.ipRanges.cidrAddress)
                Countries                         = @($_.AdditionalProperties.countriesAndRegions)
                IncludeUnknownCountriesAndRegions = if ($_.AdditionalProperties.includeUnknownCountriesAndRegions) { $true } else { $false }
                CountryLookupMethod               = if ($_.AdditionalProperties.countryLookupMethod) { $_.AdditionalProperties.countryLookupMethod } else { $null }
            }
        }

        #---------------------------------------------------------------------
        # 8. Combine and return results
        #---------------------------------------------------------------------
        $result = [PSCustomObject]@{
            Policies       = $policyObjects
            NamedLocations = $namedLocationObjects
        }

        return $result
    }
    catch {
        Write-Error "Get-ConditionalAccessConfiguration failed: $_"
    }
    finally {
        if (-not $UseExistingGraphSession) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
