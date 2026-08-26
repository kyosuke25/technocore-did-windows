$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$plainBase64 = [Console]::In.ReadToEnd().Trim()
if ([string]::IsNullOrWhiteSpace($plainBase64)) {
    throw 'Plaintext input is empty.'
}

$plain = [Convert]::FromBase64String($plainBase64)
$protected = [Security.Cryptography.ProtectedData]::Protect(
    $plain,
    $null,
    [Security.Cryptography.DataProtectionScope]::CurrentUser
)

[Console]::Out.Write([Convert]::ToBase64String($protected))
