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

# 将 Windows PowerShell 脚本通过 stdin 管道传入远程执行（一次 SSH，无长度限制）
# 注意：远端命令不要加双引号——PS 5.1 给原生 ssh.exe 传参时不保留内嵌双引号，
# 脚本体不含空格可作为单个 argv 原样送达远端。
function 通过管道执行远程Windows脚本 {
    param([string]$脚本内容, [string[]]$SSH参数)
    $编码脚本 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($脚本内容))
    $编码脚本 | ssh @SSH参数 'powershell -NoProfile -Command $s=[Console]::In.ReadToEnd();iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)))'
    return [int]$LASTEXITCODE
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
                }
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
        function Get-RemotePlatform {
            $detectionOutput = ssh @sshArguments 'cmd /c echo __SSH_COPY_ID_WINDOWS__' 2>&1
            $detectionExitCode = [int]$LASTEXITCODE
            $detectionText = ($detectionOutput | Out-String)
            if($detectionExitCode -eq 0 -and $detectionText -like '*__SSH_COPY_ID_WINDOWS__*') {
                return 'Windows'
            }
            return 'Unix'
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
            $remotePlatform = Get-RemotePlatform
            Write-Verbose "远程平台检测结果: $remotePlatform"

            # 第三步：按真实平台执行安装
            if($remotePlatform -eq 'Windows'){
                $exitCode = 通过管道执行远程Windows脚本 $windowsScript $sshArguments
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

        # Windows 端移除命令：通过 stdin 管道传入脚本，远程 PowerShell 从 stdin 读取执行
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
                $退出码 = 通过管道执行远程Windows脚本 $Windows脚本 $SSH参数
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