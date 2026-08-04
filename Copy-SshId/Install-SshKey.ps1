$ErrorActionPreference = "Stop"

$administratorSid = "S-1-5-32-544"
$isAdministrator = whoami /groups /fo csv |
    ConvertFrom-Csv |
    Where-Object { $_.SID -eq $administratorSid -and $_.Attributes -match "Enabled group" }

function Resolve-AuthorizedKeysPath {
    param(
        [string]$ConfiguredPath
    )

    $path = $ConfiguredPath.Trim().Trim('"') -replace '/', '\'
    if([string]::IsNullOrWhiteSpace($path) -or $path -ieq 'none') {
        return $null
    }

    $path = $path -replace '^__PROGRAMDATA__', $env:ProgramData
    $path = $path.Replace('%h', $env:USERPROFILE).Replace('%u', $env:USERNAME)

    if($path.StartsWith('~\')) {
        return Join-Path $env:USERPROFILE $path.Substring(2)
    }

    if([System.IO.Path]::IsPathRooted($path)) {
        return [Environment]::ExpandEnvironmentVariables($path)
    }

    return Join-Path $env:USERPROFILE $path
}

function Get-ConfiguredAuthorizedKeysFiles {
    $defaultAuthorizedKeys = @('.ssh/authorized_keys')
    $configPath = Join-Path $env:ProgramData 'ssh\sshd_config'
    if(!(Test-Path -LiteralPath $configPath)) {
        return $defaultAuthorizedKeys
    }

    $globalAuthorizedKeys = $null
    $administratorAuthorizedKeys = $null
    $inMatchBlock = $false
    $matchAppliesToAdministrator = $false

    foreach($rawLine in Get-Content -LiteralPath $configPath) {
        $line = ($rawLine -replace '\s+#.*$', '').Trim()
        if([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {
            continue
        }

        if($line -match '^Match\s+(.+)$') {
            $inMatchBlock = $true
            $matchCondition = $Matches[1]
            $matchAppliesToAdministrator = $isAdministrator -and (
                $matchCondition -match '(^|\s)all(\s|$)' -or
                $matchCondition -match '(^|\s)group\s+("[^"]*administrators[^"]*"|\S*administrators\S*)'
            )
            continue
        }

        if($line -match '^AuthorizedKeysFile\s+(.+)$') {
            $authorizedKeysFiles = $Matches[1] -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if($inMatchBlock) {
                if($matchAppliesToAdministrator -and -not $administratorAuthorizedKeys) {
                    $administratorAuthorizedKeys = $authorizedKeysFiles
                }
            } elseif(-not $globalAuthorizedKeys) {
                $globalAuthorizedKeys = $authorizedKeysFiles
            }
        }
    }

    if($administratorAuthorizedKeys) {
        return $administratorAuthorizedKeys
    }

    if($globalAuthorizedKeys) {
        return $globalAuthorizedKeys
    }

    return $defaultAuthorizedKeys
}

$authorizedKeys = Get-ConfiguredAuthorizedKeysFiles |
    ForEach-Object { Resolve-AuthorizedKeysPath $_ } |
    Where-Object { $_ } |
    Select-Object -First 1

if(-not $authorizedKeys) {
    throw 'No usable AuthorizedKeysFile path is configured.'
}

$sshDirectory = Split-Path -Parent $authorizedKeys
New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null

$encodedKeyText = "__ENCODED_KEY_TEXT__"
$keyText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedKeyText))
$keyLines = $keyText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if ($keyLines.Count -eq 0) {
    throw "No public key content was received."
}

$existingKeys = @()
if (Test-Path -LiteralPath $authorizedKeys) {
    $existingKeys = Get-Content -LiteralPath $authorizedKeys -Raw -ErrorAction SilentlyContinue
    if ($null -ne $existingKeys -and $existingKeys.Length -gt 0 -and -not $existingKeys.EndsWith("`n")) {
        [System.IO.File]::AppendAllText($authorizedKeys, [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    }

    $existingKeys = @(Get-Content -LiteralPath $authorizedKeys -ErrorAction SilentlyContinue)
}

# 提取密钥材质（类型+Base64，不含注释）用于去重比较
$existingKeyMaterials = $existingKeys | ForEach-Object { ($_ -split '\s+')[0..1] -join ' ' }

foreach ($keyLine in $keyLines) {
    $keyMaterial = ($keyLine -split '\s+')[0..1] -join ' '
    if ($existingKeyMaterials -notcontains $keyMaterial) {
        [System.IO.File]::AppendAllText($authorizedKeys, $keyLine + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        $existingKeys += $keyLine
        $existingKeyMaterials += $keyMaterial
    }
}

if ($isAdministrator -and ([string]::Equals($authorizedKeys, (Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'), [System.StringComparison]::OrdinalIgnoreCase))) {
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier($administratorSid)
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($administratorsSid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administratorsSid, "FullControl", "Allow")))
    Set-Acl -LiteralPath $authorizedKeys -AclObject $acl
}
