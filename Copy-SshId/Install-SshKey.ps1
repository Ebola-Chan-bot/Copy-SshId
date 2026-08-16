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

# --- 可写性检测与权限修复 ---
# administrators_authorized_keys 常由 SYSTEM 预先创建并持有（仅 SYSTEM 可写），
# 管理员会话直接写入也会 Access denied。处理策略：
# 1) takeown 夺取所有权 + icacls 授予 Administrators 完全控制；
# 2) 恢复 sshd 要求的严格 ACL（属主 Administrators 组、禁用继承、仅 SYSTEM/Administrators 可访问）；
# 3) 都失败则回退写入用户级 ~\.ssh\authorized_keys 并给出明确警告。
function Test-FileWritable {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write)
        $fs.Close()
        return $true
    } catch {
        return $false
    }
}

function Repair-AuthorizedKeysAcl {
    param([string]$Path)
    try {
        $null = & takeown.exe /f $Path 2>&1
        if($LASTEXITCODE -ne 0) { return $false }
        $null = & icacls.exe $Path /grant ($env:USERNAME + ':(F)') 2>&1
        if($LASTEXITCODE -ne 0) { return $false }
        # 恢复 sshd 要求的严格 ACL（ACL 不合规时 sshd 会拒绝读取该文件）：
        # 属主为 Administrators 组，禁用继承，仅 SYSTEM 与 Administrators 拥有完全控制
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier($administratorSid)
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetOwner($administratorsSid)
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administratorsSid, "FullControl", "Allow")))
        Set-Acl -LiteralPath $Path -AclObject $acl
        return $true
    } catch {
        return $false
    }
}

if(-not (Test-FileWritable -Path $authorizedKeys)) {
    Write-Warning "目标文件不可写：$authorizedKeys，尝试修复 ACL……"
    $repaired = Repair-AuthorizedKeysAcl -Path $authorizedKeys
    if(-not $repaired -or -not (Test-FileWritable -Path $authorizedKeys)) {
        $fallbackKeys = Join-Path $env:USERPROFILE '.ssh\authorized_keys'
        if([string]::Equals($authorizedKeys, $fallbackKeys, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "No write permission to $authorizedKeys (ACL repair also failed)."
        }
        Write-Warning "修复失败，回退到用户级文件：$fallbackKeys（sshd_config 若为管理员指定了独立密钥文件，该回退可能不生效；请在远程以管理员身份为 Administrators 组授予 ${env:ProgramData}\ssh\administrators_authorized_keys 的写入权限后重试）"
        $authorizedKeys = $fallbackKeys
        $sshDirectory = Split-Path -Parent $authorizedKeys
        New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null
    }
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
    # 仅在需要时恢复 sshd 要求的严格 ACL；失败不视为安装失败（密钥已写入，
    # 但若 sshd 因 ACL 不合规而拒绝读取，请远程手动执行：
    #   icacls ...administrators_authorized_keys）
    try {
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier($administratorSid)
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetOwner($administratorsSid)
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($administratorsSid, "FullControl", "Allow")))
        Set-Acl -LiteralPath $authorizedKeys -AclObject $acl
    } catch {
        Write-Warning "已写入公钥，但恢复 administrators_authorized_keys 的严格 ACL 失败：$_。若 sshd 拒绝读取该文件，请在远程以管理员身份手动修正其 ACL。"
    }
}
