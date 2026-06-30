# 将 Windows PowerShell 脚本通过 stdin 管道传入远程执行（一次 SSH，无长度限制）
function 通过管道执行远程Windows脚本 {
    param([string]$脚本内容, [string[]]$SSH参数)
    $编码脚本 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($脚本内容))
    $编码脚本 | ssh @SSH参数 'powershell -NoProfile -Command "$s=[Console]::In.ReadToEnd();iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)))"'
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

        $unixCommand = 'cd; umask 077; mkdir -p ".ssh" && touch ".ssh/authorized_keys" && { [ -z "$(tail -c 1 ".ssh/authorized_keys" 2>/dev/null)" ] || echo >> ".ssh/authorized_keys"; } && while IFS= read -r key || [ -n "$key" ]; do [ -n "$key" ] || continue; grep -qxF "$key" ".ssh/authorized_keys" || printf "%s\n" "$key" >> ".ssh/authorized_keys"; done || exit 1; '

        $keyText = Get-Content -LiteralPath $KeyFile -Raw
        $encodedKeyText = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($keyText))
        $windowsScript = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-SshKey.ps1') -Raw).Replace('__ENCODED_KEY_TEXT__', $encodedKeyText)

        function Get-RemotePlatform {
            $detectionArguments = @('-v', '-o', 'BatchMode=yes') + $sshArguments
            $detectionOutput = ssh @detectionArguments 'cmd /c echo __SSH_COPY_ID_WINDOWS__' 2>&1
            $detectionText = $detectionOutput -join "`n"

            if($detectionText -like '*__SSH_COPY_ID_WINDOWS__*') {
                return 'Windows'
            }

            if($detectionText -match 'OpenSSH_for_Windows') {
                return 'Windows'
            }

            if($detectionText -match 'Remote protocol version|Authentications that can continue|Permission denied') {
                return 'Unix'
            }

            return 'Unknown'
        }

        function Invoke-KeyInstallCommand {
            param(
                [string]$Command,
                [switch]$PipeKey
            )

            if($PipeKey){
                Get-Content $KeyFile | ssh @sshArguments $Command
            }else{
                ssh @sshArguments $Command
            }
            return [int]$LASTEXITCODE
        }

        try{
            $remotePlatform = Get-RemotePlatform

            if($remotePlatform -eq 'Unix'){
                $exitCode = Invoke-KeyInstallCommand -Command $unixCommand -PipeKey
            }elseif($remotePlatform -eq 'Windows'){
                $exitCode = 通过管道执行远程Windows脚本 $windowsScript $sshArguments
            }else{
                $exitCode = Invoke-KeyInstallCommand -Command $unixCommand -PipeKey
                if($exitCode -ne 0){
                    Write-Verbose "Unix install command failed. Trying Windows install command."
                    $exitCode = 通过管道执行远程Windows脚本 $windowsScript $sshArguments
                }
            }

            if($exitCode -ne 0){
                Write-Warning "An error occurred when installing the key"
            }
        } catch {
            Write-Warning "An error occurred when installing the key"
            Write-Host $_
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

        # Unix 端移除命令
        $Unix命令 = 'cd; umask 077; while IFS= read -r key || [ -n "$key" ]; do [ -n "$key" ] || continue; if [ -f ".ssh/authorized_keys" ]; then grep -v -xF "$key" ".ssh/authorized_keys" > ".ssh/authorized_keys.tmp" && mv ".ssh/authorized_keys.tmp" ".ssh/authorized_keys"; fi; done'

        # Windows 端移除命令：通过 stdin 管道传入脚本，远程 PowerShell 从 stdin 读取执行
        $编码密钥文本 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($密钥文本))
        $Windows脚本 = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-SshKey.ps1') -Raw).Replace('__ENCODED_KEY_TEXT__', $编码密钥文本)

        function 获取远程平台 {
            $检测参数 = @('-v', '-o', 'BatchMode=yes') + $SSH参数
            $检测输出 = ssh @检测参数 'cmd /c echo __SSH_COPY_ID_WINDOWS__' 2>&1
            $检测文本 = $检测输出 -join "`n"
            if($检测文本 -like '*__SSH_COPY_ID_WINDOWS__*') { return 'Windows' }
            if($检测文本 -match 'OpenSSH_for_Windows') { return 'Windows' }
            if($检测文本 -match 'Remote protocol version|Authentications that can continue|Permission denied') { return 'Unix' }
            return 'Unknown'
        }

        function 执行密钥移除命令 {
            param([string]$命令, [switch]$管道输入密钥)
            if($管道输入密钥){ $密钥文本 | ssh @SSH参数 $命令 }else{ ssh @SSH参数 $命令 }
            return [int]$LASTEXITCODE
        }

        function 检测是否仍有免密登录 {
            $检测输出 = ssh @SSH参数免密 'echo OK' 2>&1
            return ($检测输出 -join "`n") -like '*OK*'
        }

        try{
            if(-not (检测是否仍有免密登录)){
                Write-Host "目标主机上已无本机公钥，无需移除。"
                return
            }
            # 实际删除操作不需要 BatchMode，让 SSH 正常询问密码或使用密钥
            $远程平台 = 获取远程平台
            if($远程平台 -eq 'Unix'){
                $退出码 = 执行密钥移除命令 -命令 $Unix命令 -管道输入密钥
            }elseif($远程平台 -eq 'Windows'){
                $退出码 = 通过管道执行远程Windows脚本 $Windows脚本 $SSH参数
            }else{
                $退出码 = 执行密钥移除命令 -命令 $Unix命令 -管道输入密钥
                if($退出码 -ne 0){
                    Write-Verbose "Unix 移除命令失败，尝试 Windows 移除命令。"
                    $退出码 = 通过管道执行远程Windows脚本 $Windows脚本 $SSH参数
                }
            }
            if($退出码 -ne 0){ Write-Warning "移除密钥时发生错误" }
        } catch {
            Write-Warning "移除密钥时发生错误"
            Write-Host $_
        }
    }
}

Export-ModuleMember -Function Copy-SshId, Remove-SshId