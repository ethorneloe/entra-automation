# Load static data
$script:CountryCodeLookup = . "$PSScriptRoot\data\CountryCodeLookup.ps1"

# Load private functions
$privateFunctions = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'functions/private') -Filter *.ps1 -Recurse
foreach ($privateFunction in $privateFunctions) {
    . $privateFunction.FullName
}

# Load public functions
$publicFunctions = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'functions/public') -Filter *.ps1 -Recurse
foreach ($publicFunction in $publicFunctions) {
    . $publicFunction.FullName
    Export-ModuleMember -Function $publicFunction.Basename
}