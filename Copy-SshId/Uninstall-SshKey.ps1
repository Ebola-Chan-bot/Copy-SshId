$ErrorActionPreference = "Stop"

# 管理员 SID，用于判断当前用户是否以管理员身份运行
$管理员Sid = "S-1-5-32-544"
$是否为管理员 = whoami /groups /fo csv |
    ConvertFrom-Csv |
    Where-Object { $_.SID -eq $管理员Sid -and $_.Attributes -match "Enabled group" }

# 解析 sshd_config 中配置的 AuthorizedKeysFile 路径为实际文件系统路径
function 解析授权密钥路径 {
    param(
        [string]$配置路径
    )

    $路径 = $配置路径.Trim().Trim('"') -replace '/', '\'
    if([string]::IsNullOrWhiteSpace($路径) -or $路径 -ieq 'none') {
        return $null
    }

    $路径 = $路径 -replace '^__PROGRAMDATA__', $env:ProgramData
    $路径 = $路径.Replace('%h', $env:USERPROFILE).Replace('%u', $env:USERNAME)

    if($路径.StartsWith('~\')) {
        return Join-Path $env:USERPROFILE $路径.Substring(2)
    }

    if([System.IO.Path]::IsPathRooted($路径)) {
        return [Environment]::ExpandEnvironmentVariables($路径)
    }

    return Join-Path $env:USERPROFILE $路径
}

# 从 sshd_config 中读取 AuthorizedKeysFile 配置（支持 Match 块）
function 获取配置的授权密钥文件 {
    $默认授权密钥 = @('.ssh/authorized_keys')
    $配置路径 = Join-Path $env:ProgramData 'ssh\sshd_config'
    if(!(Test-Path -LiteralPath $配置路径)) {
        return $默认授权密钥
    }

    $全局授权密钥文件 = $null
    $管理员授权密钥文件 = $null
    $在匹配块中 = $false
    $匹配适用管理员 = $false

    foreach($原始行 in Get-Content -LiteralPath $配置路径) {
        $行 = ($原始行 -replace '\s+#.*$', '').Trim()
        if([string]::IsNullOrWhiteSpace($行) -or $行.StartsWith('#')) {
            continue
        }

        if($行 -match '^Match\s+(.+)$') {
            $在匹配块中 = $true
            $匹配条件 = $Matches[1]
            $匹配适用管理员 = $是否为管理员 -and (
                $匹配条件 -match '(^|\s)all(\s|$)' -or
                $匹配条件 -match '(^|\s)group\s+("[^"]*administrators[^"]*"|\S*administrators\S*)'
            )
            continue
        }

        if($行 -match '^AuthorizedKeysFile\s+(.+)$') {
            $授权密钥文件列表 = $Matches[1] -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if($在匹配块中) {
                if($匹配适用管理员 -and -not $管理员授权密钥文件) {
                    $管理员授权密钥文件 = $授权密钥文件列表
                }
            } elseif(-not $全局授权密钥文件) {
                $全局授权密钥文件 = $授权密钥文件列表
            }
        }
    }

    if($管理员授权密钥文件) {
        return $管理员授权密钥文件
    }

    if($全局授权密钥文件) {
        return $全局授权密钥文件
    }

    return $默认授权密钥
}

$授权密钥文件路径 = 获取配置的授权密钥文件 |
    ForEach-Object { 解析授权密钥路径 $_ } |
    Where-Object { $_ } |
    Select-Object -First 1

if(-not $授权密钥文件路径) {
    throw '没有可用的 AuthorizedKeysFile 路径配置。'
}

# 解码传入的 Base64 编码密钥文本，提取要移除的密钥行
$编码密钥文本 = "__ENCODED_KEY_TEXT__"
$密钥文本 = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($编码密钥文本))
$要移除的密钥行 = @($密钥文本 -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if ($要移除的密钥行.Count -eq 0) {
    throw "没有收到任何公钥内容。"
}

if (-not (Test-Path -LiteralPath $授权密钥文件路径)) {
    # 文件不存在，没有需要移除的密钥，直接退出
    exit 0
}

# 提取要移除密钥的材质（类型+Base64，不含注释）
$要移除的密钥材质 = $要移除的密钥行 | ForEach-Object { ($_ -split '\s+')[0..1] -join ' ' }

# 读取现有密钥，只保留材质不匹配的行，写回文件
$已有密钥 = @(Get-Content -LiteralPath $授权密钥文件路径 -ErrorAction SilentlyContinue |
    Where-Object { $行 = $_; $已有材质 = ($行 -split '\s+')[0..1] -join ' '; -not ($要移除的密钥材质 -contains $已有材质) })

# 以 UTF-8（无 BOM）编码写回文件
[System.IO.File]::WriteAllLines($授权密钥文件路径, $已有密钥, [Text.UTF8Encoding]::new($false))

# 如果写入的是 administrators_authorized_keys，修正文件 ACL
if ($是否为管理员 -and ([string]::Equals($授权密钥文件路径, (Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'), [System.StringComparison]::OrdinalIgnoreCase))) {
    $系统Sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $管理员组Sid = New-Object System.Security.Principal.SecurityIdentifier($管理员Sid)
    $访问控制列表 = New-Object System.Security.AccessControl.FileSecurity
    $访问控制列表.SetOwner($管理员组Sid)
    $访问控制列表.SetAccessRuleProtection($true, $false)
    $访问控制列表.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($系统Sid, "FullControl", "Allow")))
    $访问控制列表.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($管理员组Sid, "FullControl", "Allow")))
    Set-Acl -LiteralPath $授权密钥文件路径 -AclObject $访问控制列表
}
