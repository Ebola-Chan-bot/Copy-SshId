# ===== askpass 密码复用（单次密码）=====
# 原理：OpenSSH 从 TTY 读密码，不接受 stdin 管道；但设置了 SSH_ASKPASS（且 DISPLAY、
# SSH_ASKPASS_REQUIRE=force）后会改从该程序读密码。这里收集一次密码存入进程环境变量，
# SSH_ASKPASS 指向模块内固定的辅助脚本（Read-SshPassword.ps1），脚本从环境变量读密码——
# 之后每次 ssh 连接都自动复用同一密码。不落盘、无后台进程、无临时文件。

# 收集一次密码（SecureString），返回明文供环境变量传递（用完即清）
function 请求-Ssh密码 {
    param([string]$目标描述)
    $sec = Read-Host "输入 $目标描述 的密码" -AsSecureString
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}

# 密钥缺失时自动生成 ed25519 密钥对（无口令），返回公钥路径；失败返回 $null。
# $公钥文件 为目标公钥路径（*.pub）；默认生成在 ~\.ssh\id_ed25519
function 新建-Ssh密钥 {
    param([string]$公钥文件 = (Join-Path $env:USERPROFILE '.ssh\id_ed25519.pub'))
    if(-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Warning '本机未找到 ssh-keygen，无法自动生成 SSH 密钥。请安装 OpenSSH 客户端，或手动执行 ssh-keygen -t ed25519 后重试。'
        return $null
    }
    # ssh-keygen -f 需要不带 .pub 的私钥路径
    $密钥路径 = $公钥文件 -replace '\.pub$', ''
    if(Test-Path -LiteralPath $密钥路径 -PathType Leaf) {
        Write-Warning "私钥已存在但缺少公钥（$公钥文件），无法自动补全，请手动处理。"
        return $null
    }
    $密钥目录 = Split-Path -Parent $密钥路径
    if($密钥目录 -and -not (Test-Path -LiteralPath $密钥目录)) {
        $null = New-Item -Path $密钥目录 -ItemType Directory -ErrorAction SilentlyContinue
    }
    Write-Host "本机尚未生成 SSH 密钥，正在自动生成（ed25519，无口令）：$密钥路径"
    $null = & ssh-keygen -t ed25519 -f $密钥路径 -N '""' 2>&1
    if($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $公钥文件 -PathType Leaf)) {
        Write-Warning '自动生成 SSH 密钥失败。可手动执行 ssh-keygen -t ed25519 后重试。'
        return $null
    }
    Write-Host "SSH 密钥已生成：$公钥文件"
    return $公钥文件
}

# 启动 askpass：密码写入进程环境变量，SSH_ASKPASS 指向模块内固定的辅助脚本
function 启动-Askpass服务 {
    param([string]$密码)
    $helper = Join-Path $PSScriptRoot 'Read-SshPassword.ps1'
    $env:密码 = $密码
    $env:SSH_ASKPASS = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$helper`""
    $env:DISPLAY = 'localhost:0'
    $env:SSH_ASKPASS_REQUIRE = 'force'
}

# 停止 askpass：清除环境变量（含密码）
function 停止-Askpass服务 {
    $env:密码 = $null
    $env:SSH_ASKPASS = $null
    $env:SSH_ASKPASS_REQUIRE = $null
    $env:DISPLAY = $null
}

# 在远程 Windows 主机执行 PowerShell 脚本：scp 上传 + EncodedCommand 引导执行（不用 stdin 管道、不用超长命令行）。
# 方案演进：
#   1) stdin 管道（远端 [Console]::In.ReadToEnd()）：经 cpolar 等 NAT 隧道时 EOF 有时送达不了 → 永久挂起；
#   2) 整脚本 base64 内嵌进 ssh 命令参数：脚 base64 后约 7KB，超 cmd 命令行 8191 上限
#      → 'The command line is too long.'；
#   3) 现行方案：脚本写本地临时文件 → scp -O 上传到远端用户目录（文件传输走数据通道，
#      隧道下同样稳定）→ 一条短命令经 -EncodedCommand 引导执行（纯 base64，远端默认 shell
#      无论是 cmd 还是 PowerShell 都不会拆解它），引导脚本执行完毕自行删除远端临时文件。
function 通过scp执行远程Windows脚本 {
    param([string]$脚本内容, [string[]]$SSH参数, [string]$远程用户, [string]$远程端口, [string]$远程主机)

    $随机名 = 'sshcopyid_' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '.ps1'
    $本地临时文件 = Join-Path $env:TEMP $随机名
    Set-Content -LiteralPath $本地临时文件 -Value $脚本内容 -Encoding UTF8

    # 上传：-O 强制传统 SCP 协议（不依赖远端 sftp 子系统），目标路径相对远端用户目录
    $scp参数 = @('-O', '-P', $远程端口)
    if($远程用户){ $远程目标 = "${远程用户}@${远程主机}:$随机名" } else { $远程目标 = "${远程主机}:$随机名" }

    try {
        Write-Verbose "通过 scp 上传临时脚本到远程主机：$随机名"
        $null = scp @scp参数 $本地临时文件 $远程目标 2>&1
        if($LASTEXITCODE -ne 0){
            Write-Warning 'scp 上传脚本文件失败。公钥未写入。'
            return 1
        }

        # 引导脚本：执行已上传的文件 → 记录退出码 → 删除远端临时文件 → 原样返回退出码。
        # 整体 -EncodedCommand 编码后只有纯 base64，远端任何 shell 都不会拆解；
        # -ExecutionPolicy Bypass 保证文件执行不受远端执行策略限制。
        $引导脚本模板 = @'
$ProgressPreference = 'SilentlyContinue'
$p = Join-Path $env:USERPROFILE '__REMOTE_SCRIPT_NAME__'
& $p
$ec = $LASTEXITCODE
Remove-Item $p -Force -ErrorAction SilentlyContinue
exit $ec
'@
        $引导脚本 = $引导脚本模板.Replace('__REMOTE_SCRIPT_NAME__', $随机名)
        $编码引导 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($引导脚本))
        Write-Verbose '执行引导：调用远程临时脚本并自清理'
        ssh @SSH参数 "cmd /c powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $编码引导"
        return [int]$LASTEXITCODE
    } finally {
        Remove-Item -LiteralPath $本地临时文件 -Force -ErrorAction SilentlyContinue
    }
}

# 通过 base64 参数在远程执行 sh 脚本：脚本整体 base64 编码后作为 ssh 参数，
# 远端解码后经管道交给 sh。base64 只含 A-Za-z0-9+/=，无空格/引号，
# 不受 PS 5.1 传参吞引号影响，也避免多行脚本经 PowerShell 管道被逐行拆分的问题。
function 通过base64执行远程sh脚本 {
    param([string]$脚本内容, [string[]]$SSH参数)
    $编码脚本 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($脚本内容))
    Write-Verbose '以 base64 参数方式在远程执行 sh 脚本'
    ssh @SSH参数 "`$(echo $编码脚本 | base64 -d | sh)"
    return [int]$LASTEXITCODE
}

function Copy-SshId
{
<#
.SYNOPSIS
    Appends a public key to a machines ~/.ssh/authorized_keys file.
    Existing keys are skipped instead of being appended again.

.DESCRIPTION
    Copy-SshId is a PowerShell script that uses ssh to log into a remote machine and append the
    indicated identity file to that machine's ~/.ssh/authorized_keys file. By default, it installs the key(s) stored in "$env:USERPROFILE\.ssh\id_rsa.pub", or the first common public key found in .ssh if that file does not exist.
    Keys already present in authorized_keys are skipped.

.PARAMETER RemoteHost
    Specifies the IP or DNS name of the machine to install the public key on.

.PARAMETER RemoteUser
    Specifies which user's authorized_keys file that the key will be installed under.

.PARAMETER KeyFile
    A path of the keyfile to be installed.

.PARAMETER RemotePort
    SSH will attempt to connect to this port on the remote host. Defaults to 22

.INPUTS

    None at the moment.

.OUTPUTS

    None at the moment.

.EXAMPLE

    PS> Copy-SshId root@172.16.1.10

.EXAMPLE

    PS> Copy-SshId 172.16.1.10 -l root

.EXAMPLE

    PS> Copy-SshId 172.16.1.10 -p 2222

.EXAMPLE

    PS> Copy-SshId root@172.16.1.10 -i C:\users\n8tg\SpecialKeyDir\key.pub

.EXAMPLE

    PS> Copy-SshId -RemoteHost 172.16.1.10 -RemoteUser root

.EXAMPLE

    PS> Copy-SshId -RemoteHost 172.16.1.10 -RemoteUser root -KeyFile C:\users\n8tg\SpecialKeyDir\key.pub

.NOTES

    If no username is supplied using -RemoteUser or the User@RemoteHost syntax, the user running the command's username will be used.

.LINK

https://github.com/Ebola-Chan-bot/Copy-SshId
#>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$false)]
        [string]
        $RemoteHost,

        [Alias('l')]
        [string]
        $RemoteUser,

        [Alias('p')]
        [string]
        $RemotePort = 22,

        [Alias('i')]
        [string]
        $KeyFile = "$env:USERPROFILE\.ssh\id_rsa.pub"
    )

    PROCESS {

        if($RemoteHost.Contains("@")){
            $RemoteHostParts = $RemoteHost -split "@", 2
            $RemoteUser = $RemoteHostParts[0]
            $RemoteHost = $RemoteHostParts[1]
        }

        # Check key file is there
        if(!(Test-Path -LiteralPath $KeyFile -PathType Leaf)) {
            if(-not $PSBoundParameters.ContainsKey('KeyFile')) {
                $sshDirectory = Join-Path $env:USERPROFILE '.ssh'
                $commonKeyFileNames = @(
                    'id_ed25519.pub',
                    'id_ecdsa.pub',
                    'id_ecdsa_sk.pub',
                    'id_ed25519_sk.pub',
                    'id_rsa.pub',
                    'id_xmss.pub',
                    'id_dsa.pub'
                )

                $fallbackKeyFile = $commonKeyFileNames |
                    ForEach-Object { Join-Path $sshDirectory $_ } |
                    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                    Select-Object -First 1

                if($fallbackKeyFile) {
                    $KeyFile = $fallbackKeyFile
                    Write-Verbose "Using public key file '$KeyFile'."
                } else {
                    # 本机还没有任何 SSH 密钥：自动生成 ed25519 密钥对，再继续安装流程
                    Write-Verbose '本机尚未生成任何 SSH 密钥，尝试自动生成……'
                    $KeyFile = 新建-Ssh密钥
                    if(-not $KeyFile) { return }
                }
            } else {
                Write-Warning '未找到密钥文件，尝试在当前路径自动生成……'
                $KeyFile = 新建-Ssh密钥 -公钥文件 $KeyFile
                if(-not $KeyFile) { return }
            }
        }

        if(!(Test-Path -LiteralPath $KeyFile -PathType Leaf)) { Write-Warning "Specified key file not found"; return }

        $sshArguments = @('-p', $RemotePort)
        if($RemoteUser){
            $sshArguments += @('-l', $RemoteUser)
        }
        $sshArguments += $RemoteHost

        # 公钥经 heredoc 内嵌进 sh 脚本，整体 base64 后作为 ssh 参数在远端解码执行。
        # 安装的同时清理 authorized_keys 中的异常行：空行、以及不以合法公钥算法前缀开头的行
        # （例如终端回显被误写入的噪声行）。保留所有合法公钥行，整体去重后原子写回。
        $keyText = Get-Content -LiteralPath $KeyFile -Raw
        $keyLines = @($keyText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if($keyLines.Count -eq 0){ Write-Warning "公钥文件为空"; return }
        $escapedKeyLines = $keyLines -join "`n"
        $unixScript = @'
cd || exit 1
umask 077
mkdir -p .ssh
ak=.ssh/authorized_keys
touch "$ak"
tmp="$ak.sshcopyid.tmp"
# 1) 过滤现有文件：只保留以合法公钥算法前缀开头的非空行（删除空行与噪声行）
awk 'NF && /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-|sk-ssh-ed25519|sk-ecdsa-sha2-)/' "$ak" > "$tmp" 2>/dev/null
# 2) 追加本机公钥（若不在保留结果中）
while IFS= read -r key || [ -n "$key" ]; do
    [ -n "$key" ] || continue
    grep -qxF "$key" "$tmp" || printf '%s\n' "$key" >> "$tmp"
done <<'__SSH_COPY_ID_KEYS__'
__KEYS__
__SSH_COPY_ID_KEYS__
# 3) 整体去重（sort -u 同时会排好序）
sort -u "$tmp" -o "$tmp"
# 4) 原子写回：先写临时文件再覆盖原文件，属主/属组不变（写已存在文件）
chmod 600 "$tmp"
cat "$tmp" > "$ak"
rm -f "$tmp"
'@
        # 把公钥内容填进 heredoc 占位符（避免在 here-string 里做复杂转义）
        $unixScript = $unixScript.Replace('__KEYS__', $escapedKeyLines)

        $keyText = Get-Content -LiteralPath $KeyFile -Raw
        $encodedKeyText = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($keyText))
        $windowsScript = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-SshKey.ps1') -Raw).Replace('__ENCODED_KEY_TEXT__', $encodedKeyText)

        # 平台检测：只在【登录已成功】的前提下调用（此时连接必然已认证）。
        # cmd 执行成功(0 且含标记) → Windows；否则(非 0) → Unix。绝不再返回 Unknown。
        # Windows 时用 reg.exe 探测 OpenSSH 默认 shell：cmd/powershell 均可安全执行 reg query，
        # 不受远端默认 shell 差异影响（命令中无 $、无引号转义陷阱）。
        # 返回 [PSCustomObject]：平台 ('Windows'/'Unix')、默认Shell ('PowerShell'/'cmd'/'')。
        function Get-RemotePlatform {
            $detectionOutput = ssh @sshArguments 'cmd /c echo __SSH_COPY_ID_WINDOWS__' 2>&1
            $detectionExitCode = [int]$LASTEXITCODE
            $detectionText = ($detectionOutput | Out-String)
            if($detectionExitCode -ne 0 -or $detectionText -notlike '*__SSH_COPY_ID_WINDOWS__*') {
                return [PSCustomObject]@{ 平台 = 'Unix'; 默认Shell = '' }
            }
            $regOutput = ssh @sshArguments 'reg query HKLM\SOFTWARE\OpenSSH /v DefaultShell' 2>&1
            $regText = ($regOutput | Out-String)
            $默认Shell = 'cmd'
            if($regText -match 'powershell\.exe' -or $regText -match 'pwsh\.exe') {
                $默认Shell = 'PowerShell'
            }
            return [PSCustomObject]@{ 平台 = 'Windows'; 默认Shell = $默认Shell }
        }

        $使用密码 = $false
        $密码 = $null
        try{
            # 第一步：先试免密登录（BatchMode 不弹密码）。免密成功说明公钥已生效，无需安装。
            Write-Verbose '尝试免密登录…'
            $免密输出 = ssh -o BatchMode=yes @sshArguments 'echo __SSH_COPY_ID_LOGIN_OK__' 2>&1
            $免密退出码 = [int]$LASTEXITCODE

            if($免密退出码 -eq 0){
                Write-Host '目标主机已可免密登录（公钥已存在），无需安装。'
                return
            }

            # 免密失败：收集一次密码，启动 askpass 服务，之后所有连接复用该密码
            Write-Verbose '免密不可用，改用密码（将只询问一次，后续连接复用）。'
            $密码 = 请求-Ssh密码 -目标描述 "$RemoteUser@$RemoteHost"
            启动-Askpass服务 -密码 $密码
            $密码 = $null   # 明文只留在 pipe 服务 runspace 里，主作用域立即清除
            $使用密码 = $true

            # 用密码登录验证（askpass 自动供密码，不弹提示）
            Write-Verbose '正在用密码登录远程主机…'
            $loginOutput = ssh @sshArguments 'echo __SSH_COPY_ID_LOGIN_OK__' 2>&1
            $loginExit = [int]$LASTEXITCODE
            $loginText = ($loginOutput | Out-String)
            if($loginExit -ne 0){
                if($loginText -match 'Not allowed|Connection closed|Connection reset|kex_exchange_identification'){
                    Write-Warning '服务器在认证前主动断开了连接（可能是 fail2ban/防火墙临时封禁或访问控制）。请稍后重试、更换网络或联系管理员。'
                }else{
                    Write-Warning '密码认证失败（密码错误）。未进行任何平台操作。'
                }
                return
            }
            Write-Verbose '登录成功。'

            # 第二步：登录成功后做平台检测（askpass 复用密码，不再弹密码）
            $检测结果 = Get-RemotePlatform
            $remotePlatform = $检测结果.平台
            Write-Verbose "远程平台检测结果: $remotePlatform（Windows 时默认 shell: $($检测结果.默认Shell)）"

            # 第三步：按真实平台执行安装
            if($remotePlatform -eq 'Windows'){
                # Windows 且 OpenSSH 默认 shell 是 cmd 时，把它改成 PowerShell。
                # 仅 Copy-SshId 负责设置；Remove-SshId 不会还原该配置（用户要求：一次改好，不再变回去）。
                # best-effort：写 HKLM 需要管理员权限，无权限时只警告，不阻断密钥安装。
                if($检测结果.默认Shell -eq 'cmd'){
                    Write-Verbose '远程 OpenSSH 默认 shell 为 cmd，尝试切换为 PowerShell……'
                    $切换脚本 = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Set-DefaultShell.ps1') -Raw
                    $切换结果 = 通过scp执行远程Windows脚本 $切换脚本 $sshArguments -远程用户 $RemoteUser -远程端口 $RemotePort -远程主机 $RemoteHost 2>&1
                    $切换文本 = ($切换结果 | Out-String)
                    if($切换文本 -like '*SHELL_SET*'){
                        Write-Host '远程 OpenSSH 默认 shell 已切换为 PowerShell（Remove-SshId 不会还原此设置）。'
                    }elseif($切换文本 -like '*ALREADY_POWERSHELL*'){
                        Write-Verbose '远程默认 shell 已经是 PowerShell，无需切换。'
                    }else{
                        Write-Warning "默认 shell 切换为 PowerShell 失败（$切换文本）。不影响密钥安装，继续。"
                    }
                }
                $exitCode = 通过scp执行远程Windows脚本 $windowsScript $sshArguments -远程用户 $RemoteUser -远程端口 $RemotePort -远程主机 $RemoteHost
            }else{
                $exitCode = 通过base64执行远程sh脚本 $unixScript $sshArguments
            }

            Write-Verbose "安装结束，退出码: $exitCode"
            if($exitCode -eq 255){
                Write-Warning '安装过程中 SSH 连接被断开，公钥可能未写入。'
            }elseif($exitCode -ne 0){
                Write-Warning 'An error occurred when installing the key'
            }
        } catch {
            Write-Warning "An error occurred when installing the key"
            Write-Host $_
        } finally {
            if($使用密码){ 停止-Askpass服务 }
        }
    }
}

# 从目标主机上移除本机公钥，恢复密码登录

function Remove-SshId
{
<#
.SYNOPSIS
    从目标主机的 ~/.ssh/authorized_keys 中移除本机公钥，使该主机恢复需要密码登录的状态。

.DESCRIPTION
    Remove-SshId 通过 SSH 登录远程主机，从指定用户的 authorized_keys 文件中删除本机公钥。
    删除后，该远程主机将不再接受本机的免密登录，恢复为需要密码认证。

.PARAMETER RemoteHost
    目标主机的 IP 地址或 DNS 名称。

.PARAMETER RemoteUser
    目标主机上要移除免密登录许可的用户名。

.PARAMETER KeyFile
    要移除的密钥文件路径。未指定时，将移除本机 ~\\.ssh 目录下所有公钥在远程主机上的对应条目。

.PARAMETER RemotePort
    SSH 连接端口，默认为 22。

.EXAMPLE

    PS> Remove-SshId root@172.16.1.10

.EXAMPLE

    PS> Remove-SshId 172.16.1.10 -l root

.EXAMPLE

    PS> Remove-SshId root@172.16.1.10 -p 2222

.EXAMPLE

    PS> Remove-SshId -RemoteHost 172.16.1.10 -RemoteUser root

.NOTES

    如果未通过 -RemoteUser 或 User@RemoteHost 语法提供用户名，将使用当前 Windows 用户名。
    未指定 -KeyFile 时，会自动搜索 ~\\.ssh 下所有 .pub 文件并全部移除。

.LINK

https://github.com/Ebola-Chan-bot/Copy-SshId
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$false)]
        [string]
        $RemoteHost,

        [Alias('l')]
        [string]
        $RemoteUser,

        [Alias('p')]
        [string]
        $RemotePort = 22,

        [Alias('i')]
        [string]
        $KeyFile

    )

    PROCESS {

        # 解析 User@Host 语法
        if($RemoteHost.Contains("@")){
            $主机部分 = $RemoteHost -split "@", 2
            $RemoteUser = $主机部分[0]
            $RemoteHost = $主机部分[1]
        }

        # 如果未指定 -KeyFile，则收集本机 ~\.ssh 下所有公钥
        if(-not $PSBoundParameters.ContainsKey('KeyFile')){
            $SSH目录 = Join-Path $env:USERPROFILE '.ssh'
            $常见密钥模式 = @('*.pub')
            $所有公钥文件 = Get-ChildItem -LiteralPath $SSH目录 -Filter '*.pub' -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
            if($所有公钥文件){
                Write-Verbose "将移除 $($所有公钥文件.Count) 个公钥：$($所有公钥文件.Name -join ', ')"
            } else {
                Write-Warning "未找到任何公钥文件（$SSH目录 下无 .pub 文件）"
                return
            }
            $密钥文本 = ($所有公钥文件 | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        } else {
            if(!(Test-Path -LiteralPath $KeyFile -PathType Leaf)){
                Write-Warning "指定的密钥文件未找到"
                return
            }
            $密钥文本 = Get-Content -LiteralPath $KeyFile -Raw
        }

        $SSH参数 = @('-p', $RemotePort)
        if($RemoteUser){
            $SSH参数 += @('-l', $RemoteUser)
        }
        $SSH参数 += $RemoteHost

        # 构建带 BatchMode 的 SSH 参数，用于检测平台和免密登录状态，不弹密码提示
        $SSH参数免密 = @('-o', 'BatchMode=yes') + $SSH参数

        # Unix 端移除：公钥经 heredoc 内嵌进 sh 脚本，整体 base64 后作为 ssh 参数在远端解码执行
        $密钥行列表 = @($密钥文本 -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if($密钥行列表.Count -eq 0){ Write-Warning "没有可移除的公钥内容"; return }
        $转义密钥行 = $密钥行列表 -join "`n"
        $Unix脚本 = @"
cd || exit 1
umask 077
while IFS= read -r key || [ -n `"`$key`" ]; do
    [ -n `"`$key`" ] || continue
    if [ -f .ssh/authorized_keys ]; then
        grep -v -xF `"`$key`" .ssh/authorized_keys > .ssh/authorized_keys.tmp && mv .ssh/authorized_keys.tmp .ssh/authorized_keys
    fi
done <<'__SSH_COPY_ID_KEYS__'
$转义密钥行
__SSH_COPY_ID_KEYS__
"@

        # Windows 端移除：脚本经 scp 上传到远端用户目录，再由短引导命令
        # （-EncodedCommand）调用执行；不依赖 stdin 管道、不受命令行长度限制
        $编码密钥文本 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($密钥文本))
        $Windows脚本 = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-SshKey.ps1') -Raw).Replace('__ENCODED_KEY_TEXT__', $编码密钥文本)

        # 平台检测：只在【免密登录已成功】后调用，此连接必然已认证
        function 获取远程平台 {
            $检测输出 = ssh @SSH参数 'cmd /c echo __SSH_COPY_ID_WINDOWS__' 2>&1
            $检测退出码 = [int]$LASTEXITCODE
            $检测文本 = ($检测输出 | Out-String)
            if($检测退出码 -eq 0 -and $检测文本 -like '*__SSH_COPY_ID_WINDOWS__*') { return 'Windows' }
            return 'Unix'
        }

        try{
            # Remove-SshId 的目的是移除公钥；只有在【已能免密登录】时才有公钥可移除。
            # 因此只用免密（BatchMode 不弹密码）：免密失败说明公钥已不存在，无需移除。
            Write-Verbose '检测免密登录（仅免密有效时才需要移除公钥）…'
            $免密输出 = ssh -o BatchMode=yes @SSH参数 'echo __SSH_COPY_ID_LOGIN_OK__' 2>&1
            $免密退出码 = [int]$LASTEXITCODE

            if($免密退出码 -ne 0){
                Write-Host '目标主机上本机公钥未生效（无法免密登录），无需移除。'
                return
            }
            Write-Verbose '免密登录成功，存在可移除的公钥。'

            # 免密登录已成功，检测平台后按真实平台移除（全程免密，不弹密码）
            $远程平台 = 获取远程平台
            Write-Verbose "远程平台检测结果: $远程平台"
            if($远程平台 -eq 'Windows'){
                $退出码 = 通过scp执行远程Windows脚本 $Windows脚本 $SSH参数 -远程用户 $RemoteUser -远程端口 $RemotePort -远程主机 $RemoteHost
            }else{
                $退出码 = 通过base64执行远程sh脚本 $Unix脚本 $SSH参数
            }
            Write-Verbose "移除结束，退出码: $退出码"
            if($退出码 -eq 255){
                Write-Warning "SSH 连接失败（认证未通过或被服务器主动断开），密钥未移除。"
            }elseif($退出码 -ne 0){ Write-Warning "移除密钥时发生错误" }
        } catch {
            Write-Warning "移除密钥时发生错误"
            Write-Host $_
        }
    }
}

Export-ModuleMember -Function Copy-SshId, Remove-SshId