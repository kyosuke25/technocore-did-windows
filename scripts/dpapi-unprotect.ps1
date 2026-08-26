$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$protectedBase64 = [Console]::In.ReadToEnd().Trim()
if ([string]::IsNullOrWhiteSpace($protectedBase64)) {
    throw 'Protected input is empty.'
}

$protected = [Convert]::FromBase64String($protectedBase64)
$plain = [Security.Cryptography.ProtectedData]::Unprotect(
    $protected,
    $null,
    [Security.Cryptography.DataProtectionScope]::CurrentUser
)

[Console]::Out.Write([Convert]::ToBase64String($plain))
