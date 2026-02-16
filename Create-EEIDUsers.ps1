param(
    [string]$TenantDomain = "MarsMSCustomer.onmicrosoft.com",
    [int]$UserCount = 10000,
    [string]$UserPrefix = "dedup-test-",
    [string]$DisplayNamePrefix = "EEID User",
    [string]$OutputCsv = ".\created-users.csv"
)

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Text)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($bytes)
    }
    finally {
        $sha.Dispose()
    }

    $hex = [System.BitConverter]::ToString($hashBytes)
    return ($hex -replace '-', '').ToLowerInvariant()
}

function New-RandomPassword {
    param([int]$Length = 16)

    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lower = "abcdefghijklmnopqrstuvwxyz"
    $digits = "0123456789"
    $symbols = "!@#$%^&*()-_=+[]{}"

    $all = ($upper + $lower + $digits + $symbols).ToCharArray()
    $passwordChars = New-Object System.Collections.Generic.List[char]
    $passwordChars.Add(($upper.ToCharArray() | Get-Random)) | Out-Null
    $passwordChars.Add(($lower.ToCharArray() | Get-Random)) | Out-Null
    $passwordChars.Add(($digits.ToCharArray() | Get-Random)) | Out-Null
    $passwordChars.Add(($symbols.ToCharArray() | Get-Random)) | Out-Null

    for ($i = $passwordChars.Count; $i -lt $Length; $i++) {
        $passwordChars.Add(($all | Get-Random)) | Out-Null
    }

    $shuffled = $passwordChars | Sort-Object { Get-Random }
    return -join $shuffled
}

function Test-DedupHashExtensionProperty {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationId,
        [Parameter(Mandatory = $true)][string]$ExpectedPropertyName
    )

    $uri = "/v1.0/applications/$ApplicationId/extensionProperties"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $properties = @()
    if ($null -ne $response.value) {
        $properties = @($response.value)
    }

    $match = $properties | Where-Object { $_.name -eq $ExpectedPropertyName } | Select-Object -First 1
    if (-not $match) {
        throw "DedupHash extension property '$ExpectedPropertyName' was not found on application '$ApplicationId'."
    }

    if ([string]$match.dataType -ne "String") {
        throw "DedupHash extension property '$ExpectedPropertyName' must be dataType 'String' but found '$($match.dataType)'."
    }

    Write-Host "Verified extension property: $($match.name) (dataType=$($match.dataType))"
}

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users"
)

foreach ($requiredModule in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $requiredModule)) {
        Install-Module $requiredModule -Scope CurrentUser -Force -AllowClobber
    }
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

$scopes = @(
    "User.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Organization.Read.All",
    "Application.Read.All"
)

Connect-MgGraph -TenantId $TenantDomain -Scopes $scopes -NoWelcome

$connectedContext = Get-MgContext
if (-not $connectedContext) {
    throw "Failed to establish Microsoft Graph connection."
}

$results = New-Object System.Collections.Generic.List[object]
$extensionAppId = "d83327ed-a720-4bd4-9a8c-0bb7ba0876cd"
$dedupHashExtensionProperty = "extension_74354cb629744a0c8145534c2616c5c5_DedupHash"

Test-DedupHashExtensionProperty -ApplicationId $extensionAppId -ExpectedPropertyName $dedupHashExtensionProperty

for ($index = 1; $index -le $UserCount; $index++) {
    $rawUserName = "$UserPrefix$index"
    $dedupHash = Get-Sha256Hex -Text $rawUserName
    $dedupHashString = [string]$dedupHash
    $upn = "$dedupHashString@$TenantDomain"
    $displayName = "$DisplayNamePrefix $index"
    $mailNickname = if ($dedupHashString.Length -gt 64) { $dedupHashString.Substring(0, 64) } else { $dedupHashString }

    $existingUser = $null
    try {
        $existingUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -Property Id,UserPrincipalName -ErrorAction Stop | Select-Object -First 1
    }
    catch {
        $existingUser = $null
    }

    if ($existingUser) {
        $results.Add([pscustomobject]@{
            RawUserName = $rawUserName
            DedupHash = $dedupHashString
            UserPrincipalName = $upn
            DisplayName = $displayName
            Password = ""
            ObjectId = $existingUser.Id
            Status = "SkippedExisting"
            DedupHashAttribute = "Ignored"
        }) | Out-Null
        Write-Host "Skipped existing: $rawUserName => $upn"
        continue
    }

    $passwordPlain = New-RandomPassword -Length 16

    $userParams = @{
        AccountEnabled = $true
        DisplayName = $displayName
        MailNickname = $mailNickname
        UserPrincipalName = $upn
        PasswordProfile = @{
            Password = $passwordPlain
            ForceChangePasswordNextSignIn = $true
        }
    }

    try {
        $createdUser = New-MgUser -BodyParameter $userParams -ErrorAction Stop

        $attributeStatus = "DedupHash saved"
        try {
            Update-MgUser -UserId $createdUser.Id -BodyParameter @{
                $dedupHashExtensionProperty = $dedupHashString
            } -ErrorAction Stop
        }
        catch {
            $attributeStatus = "DedupHash not saved: $($_.Exception.Message)"
        }

        $results.Add([pscustomobject]@{
            RawUserName = $rawUserName
            DedupHash = $dedupHashString
            UserPrincipalName = $upn
            DisplayName = $displayName
            Password = $passwordPlain
            ObjectId = $createdUser.Id
            Status = "Created"
            DedupHashAttribute = $attributeStatus
        }) | Out-Null
        Write-Host "Created: $rawUserName => $upn"
    }
    catch {
        $results.Add([pscustomobject]@{
            RawUserName = $rawUserName
            DedupHash = $dedupHashString
            UserPrincipalName = $upn
            DisplayName = $displayName
            Password = $passwordPlain
            ObjectId = ""
            DedupHashAttribute = "Not attempted"
            Status = "Failed: $($_.Exception.Message)"
        }) | Out-Null
        Write-Warning "Failed: $rawUserName => $upn - $($_.Exception.Message)"
    }
}

$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

$createdCount = ($results | Where-Object { $_.Status -eq "Created" }).Count
$skippedCount = ($results | Where-Object { $_.Status -eq "SkippedExisting" }).Count
$failedCount = ($results | Where-Object { $_.Status -like "Failed:*" }).Count

Write-Host "Summary: Created=$createdCount; SkippedExisting=$skippedCount; Failed=$failedCount"
Write-Host "Done. Results written to: $OutputCsv"
