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
    param([string]$脚本内容, [string[]]$SSH参数, [string]$远程用户, [string]$远程端口, [string]$远程主机, [string[]]$加密附加参数 = @())

    $随机名 = 'sshcopyid_' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '.ps1'
    $本地临时文件 = Join-Path $env:TEMP $随机名
    Set-Content -LiteralPath $本地临时文件 -Value $脚本内容 -Encoding UTF8

    # 上传：-O 强制传统 SCP 协议（不依赖远端 sftp 子系统），目标路径相对远端用户目录；加密附加参数让 scp 走与 ssh 相同的 AEAD 加密，避开同样的 MAC 不兼容问题
    $scp参数 = @('-O', '-P', $远程端口) + $加密附加参数
    if($远程用户){ $远程目标 = "${远程用户}@${远程主机}:$随机名" } else { $远程目标 = "${远程主机}:$随机名" }

    try {
        Write-Verbose "通过 scp 上传临时脚本到远程主机：$随机名"
        $null = scp @scp参数 $本地临时文件 $远程目标 2>&1
        if($LASTEXITCODE -ne 0){
            Write-Warning 'scp 上传脚本文件失败。公钥未写入。'
            return 1
        }

        # 引导脚本：执行已上传的文件 → 记录退出码 → 删除远端临时文件 → 原样返回退出码。
        # 模板存于模块目录 Invoke-Bootstrap.ps1；整体 -EncodedCommand 编码后只有纯 base64，远端任何 shell 都不会拆解；-ExecutionPolicy Bypass 保证文件执行不受远端执行策略限制。
        $引导脚本模板 = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Invoke-Bootstrap.ps1') -Raw
        $引导脚本 = $引导脚本模板.Replace('__REMOTE_SCRIPT_NAME__', $随机名)
        $编码引导 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($引导脚本))
        Write-Verbose '执行引导：调用远程临时脚本并自清理'
        ssh @SSH参数 "cmd /c powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $编码引导"
        return [int]$LASTEXITCODE
    } finally {
        Remove-Item -LiteralPath $本地临时文件 -Force -ErrorAction SilentlyContinue
    }
}

# 通过 base64 参数在远程执行 sh 脚本：脚本整体 base64 编码后作为 ssh 参数，远端解码后经管道交给 sh。base64 只含 A-Za-z0-9+/=，无空格/引号，不受 PS 5.1 传参吞引号影响，也避免多行脚本经 PowerShell 管道被逐行拆分的问题。
# 两个必须遵守的细节（均在老系统 GNU coreutils 6.7 上实测踩过坑）：
#   1) 必须用 printf '%s' 而不是 echo 输出 base64：echo 会追加末尾换行，老版本 base64 -d 会报 "base64: invalid input" 且返回非零，导致整个执行失败；
#   2) 编码前必须把 CRLF 规范成 LF：Windows 上 here-string 的行尾是 CRLF，\r 会随 base64 原样进入远端 sh，引发 "command not found" 或 heredoc/关键字（如 do\r）语法错误；
#   3) 不要用 $(...) 命令替换包裹整条命令：脚本 stdout 会被替换结果二次执行，产生莫名错误且丢失原始输出。
function 通过base64执行远程sh脚本 {
    param([string]$脚本内容, [string[]]$SSH参数)
    $规范脚本 = $脚本内容.Replace("`r`n", "`n").Replace("`r", "`n")
    $编码脚本 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($规范脚本))
    Write-Verbose '以 base64 参数方式在远程执行 sh 脚本'
    ssh @SSH参数 "printf '%s' $编码脚本 | base64 -d | sh"
    return [int]$LASTEXITCODE
}

# 把有实现缺陷的 umac 系列 MAC 从默认候选中剔除，写进用户级 ~/.ssh/config 的 Host * 块，使终端里手敲的裸 ssh/scp/sftp/git 命令也一并避开该缺陷。
# 背景：Windows 自带 OpenSSH 客户端对 umac-*-etm 的 MAC 计算实现有缺陷（LibreSSL 侧问题，官方 PowerShell/Win32-OpenSSH#2078 标记为外部依赖且至今未修），一旦与服务器协商到 umac 必然 Corrupted MAC 断连；把它剔除后连接会落到 hmac-sha2-*-etm 或 AEAD 等实现正常的强算法，所以这既不是削弱安全也不是禁用算法家族，仅仅是在这台机器上避开用不了的实现。
# 选用户级而非系统级（ProgramData\ssh\ssh_config）：用户级无需管理员权限、不改动系统组件、且不影响本机其它用户的既有配置；选 Host * 全局降权而非单主机块：缺陷在客户端而非某台服务器，任何不提供 AEAD/chacha20 的服务器都会以同样方式触发，逐台添加只会反复踩坑。
# 幂等：以固定标记块识别，已写过则跳过；首次修改前对既有 config 做时间戳备份；按字节读写并用 UTF-8 无 BOM 追加，既保留原文件中的中文主机名也不会写入 BOM 干扰 ssh 解析。
# 返回 $true 表示本次新写入，$false 表示已存在或写入失败（失败原因已通过 Warning 报出）。
function 写入-Umac降权配置 {
    $SSH目录 = Join-Path $env:USERPROFILE '.ssh'
    $config路径 = Join-Path $SSH目录 'config'
    $起始标记 = '# BEGIN Copy-SshId UMAC-FIX'
    $结束标记 = '# END Copy-SshId UMAC-FIX'
    $配置块行 = @(
        $起始标记,
        '# 由 Copy-SshId 模块自动写入：Windows 自带 OpenSSH 客户端对 umac 系列 MAC 的计算实现有缺陷，一旦与服务器协商到就会 Corrupted MAC 断连（官方 issue PowerShell/Win32-OpenSSH#2078，至今未修）。',
        '# 下面把 umac 从默认候选中剔除（MACs 减号前缀是降权剔除语义），连接会改走 hmac-sha2-*-etm 或 AEAD 等实现正常的强算法，安全性不受影响；删掉本块即恢复默认行为。',
        'Host *',
        '    MACs -umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-64@openssh.com',
        $结束标记
    )

    if(-not (Test-Path -LiteralPath $SSH目录)){
        $null = New-Item -Path $SSH目录 -ItemType Directory -ErrorAction SilentlyContinue
    }

    $现有内容 = ''
    if(Test-Path -LiteralPath $config路径){
        $现有内容 = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($config路径))
        if($现有内容 -match [regex]::Escape($起始标记)){
            Write-Verbose '用户级 ssh config 中已存在 umac 降权配置块，跳过写入。'
            return $false
        }
    }

    # ssh_config 每个关键字首匹配生效：若文件中已有 MACs 指令，则我们追加的块不会生效，必须如实告知而不是假装修好了
    if($现有内容 -match '(?m)^\s*MACs'){
        Write-Warning "检测到 $config路径 中已存在 MACs 指令：ssh 配置首个匹配生效，自动追加的 umac 降权块可能被它覆盖而不生效。请人工检查该指令，未进行自动写入。"
        return $false
    }

    try{
        if($现有内容){
            Copy-Item -LiteralPath $config路径 -Destination "$config路径.Copy-SshId备份_$(Get-Date -Format 'yyyyMMdd_HHmmss')" -ErrorAction Stop
            Write-Verbose "已备份原 ssh config 后再修改。"
        }
        # 保证既有内容与新块之间有空行分隔，且原文件不以换行结尾时先补一个换行，避免把最后一行粘连进新块
        $前置分隔 = if($现有内容){ if($现有内容.EndsWith("`n")){ "`r`n" } else { "`r`n`r`n" } } else { '' }
        $待追加文本 = $前置分隔 + ($配置块行 -join "`r`n") + "`r`n"
        $追加字节 = [Text.Encoding]::UTF8.GetBytes($待追加文本)
        $现有字节 = if($现有内容){ [IO.File]::ReadAllBytes($config路径) } else { [byte[]]@() }
        [IO.File]::WriteAllBytes($config路径, $现有字节 + $追加字节)
        Write-Host "已自动写入 umac 降权配置到用户级 ssh config（$config路径），终端里手敲的裸 ssh/scp/git 命令也将自动避开该加密缺陷。"
        return $true
    }catch{
        Write-Warning "自动写入 ssh config 失败：$($_.Exception.Message)"
        return $false
    }
}

# 探测免密登录的同时自动检测并修复加密算法不兼容：本机 Win32-OpenSSH（9.x）与部分新版服务器（如禁用 chacha20 的 OpenSSH 10.x）协商出 aes*-ctr + umac-*-etm 组合时，客户端 MAC 计算缺陷会导致 "Corrupted MAC on input" / "message authentication code incorrect"，在认证阶段断连——与密码、公钥存在与否均无关。检测到该特征时自动改用 AEAD 加密（aes-gcm，自带完整性校验、不走独立 MAC 通路）重试探测，同时把 umac 降权持久化写进用户级 ssh config，全程不需要用户手动修改任何配置。
# 返回 [PSCustomObject]：免密输出、免密退出码（生效参数下的探测结果，调用方直接复用避免重复连接）、附加参数（空数组表示无需修复或自动修复失败，调用方应将其前置到 SSH 参数数组开头，即主机名之前）。
function 探测免密登录并修复加密 {
    param([string[]]$SSH参数)
    $AEAD参数 = @('-o', 'Ciphers=aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr')
    $输出 = ssh -o BatchMode=yes @SSH参数 'echo __SSH_COPY_ID_LOGIN_OK__' 2>&1 | Out-String
    $退出码 = [int]$LASTEXITCODE
    $附加参数 = @()
    if($输出 -match 'Corrupted MAC|message authentication code incorrect'){
        Write-Verbose '检测到加密层 MAC 校验失败：本机 OpenSSH 的 umac 实现缺陷被触发，自动降权 umac 并改用 AEAD 加密优先重试…'
        # 会话内附加参数只能修复模块自身发起的连接，用户在终端手敲的裸命令拿不到这些参数，因此必须同时把降权配置持久化进用户级 ssh config，两边一起生效
        $null = 写入-Umac降权配置
        $输出 = ssh -o BatchMode=yes @AEAD参数 @SSH参数 'echo __SSH_COPY_ID_LOGIN_OK__' 2>&1 | Out-String
        $退出码 = [int]$LASTEXITCODE
        if($输出 -notmatch 'Corrupted MAC|message authentication code incorrect'){
            $附加参数 = $AEAD参数
            Write-Host '已自动修复与服务器的加密算法不兼容（本会话强制 AEAD 加密）。'
        }
    }
    return [PSCustomObject]@{ 免密输出 = $输出; 免密退出码 = $退出码; 附加参数 = $附加参数 }
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

        # Unix 安装脚本存于模块目录 Install-SshKey.sh：公钥经 heredoc 内嵌进 sh 脚本（占位符 __KEYS__），整体 base64 后作为 ssh 参数在远端解码执行。
        # 脚本本身在安装公钥的同时会清理 authorized_keys 中的异常行（空行、不以合法公钥算法前缀开头的噪声行），保留合法公钥行并整体去重后原子写回。
        $keyText = Get-Content -LiteralPath $KeyFile -Raw
        $keyLines = @($keyText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if($keyLines.Count -eq 0){ Write-Warning "公钥文件为空"; return }
        $escapedKeyLines = $keyLines -join "`n"
        # 把公钥内容填进 heredoc 占位符（避免在脚本文件里做复杂转义）
        $unixScript = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-SshKey.sh') -Raw).Replace('__KEYS__', $escapedKeyLines)

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
            # 第一步：先试免密登录（BatchMode 不弹密码），同时自动检测并修复加密算法不兼容（MAC 损坏时改用 AEAD 参数重探，附加参数前置到主机名之前，后续所有 ssh 连接沿用）。免密成功说明公钥已生效，无需安装。
            Write-Verbose '尝试免密登录…'
            $探测结果 = 探测免密登录并修复加密 $sshArguments
            $加密附加参数 = $探测结果.附加参数
            if($加密附加参数.Count -gt 0){ $sshArguments = $加密附加参数 + $sshArguments }
            $免密退出码 = $探测结果.免密退出码

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
                if($loginText -match 'Corrupted MAC|message authentication code incorrect'){
                    # 走到这里说明已由探测阶段自动切换 AEAD 重试后仍然 MAC 损坏，属于更严重的加密层不兼容。这不是密码错误，必须如实报出，绝不能误报成密码错误让用户反复试密码。
                    Write-Warning '加密通道 MAC 校验失败（非密码错误）：自动切换 AEAD 加密后仍无法避开，属于本机 OpenSSH 与该服务器的严重不兼容。请升级本机 OpenSSH 客户端，或联系服务器管理员检查 sshd 的加密配置。'
                }elseif($loginText -match 'Not allowed|Connection closed|Connection reset|kex_exchange_identification'){
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
                    $切换结果 = 通过scp执行远程Windows脚本 $切换脚本 $sshArguments -远程用户 $RemoteUser -远程端口 $RemotePort -远程主机 $RemoteHost -加密附加参数 $加密附加参数 2>&1
                    $切换文本 = ($切换结果 | Out-String)
                    if($切换文本 -like '*SHELL_SET*'){
                        Write-Host '远程 OpenSSH 默认 shell 已切换为 PowerShell（Remove-SshId 不会还原此设置）。'
                    }elseif($切换文本 -like '*ALREADY_POWERSHELL*'){
                        Write-Verbose '远程默认 shell 已经是 PowerShell，无需切换。'
                    }else{
                        Write-Warning "默认 shell 切换为 PowerShell 失败（$切换文本）。不影响密钥安装，继续。"
                    }
                }
                $exitCode = 通过scp执行远程Windows脚本 $windowsScript $sshArguments -远程用户 $RemoteUser -远程端口 $RemotePort -远程主机 $RemoteHost -加密附加参数 $加密附加参数
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

        # Unix 端移除脚本存于模块目录 Uninstall-SshKey.sh：公钥经 heredoc 内嵌（占位符 __KEYS__），整体 base64 后作为 ssh 参数在远端解码执行
        $密钥行列表 = @($密钥文本 -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if($密钥行列表.Count -eq 0){ Write-Warning "没有可移除的公钥内容"; return }
        $转义密钥行 = $密钥行列表 -join "`n"
        $Unix脚本 = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-SshKey.sh') -Raw).Replace('__KEYS__', $转义密钥行)

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
            # 探测的同时自动检测并修复加密算法不兼容（MAC 损坏时改用 AEAD 参数重探），附加参数前置到主机名之前，后续所有 ssh/scp 连接沿用，无需用户修改任何配置
            $探测结果 = 探测免密登录并修复加密 $SSH参数
            $加密附加参数 = $探测结果.附加参数
            if($加密附加参数.Count -gt 0){ $SSH参数 = $加密附加参数 + $SSH参数 }
            $免密退出码 = $探测结果.免密退出码

            if($免密退出码 -ne 0){
                # 走到这里仍 MAC 损坏说明自动切 AEAD 也修不好，无法判断公钥是否存在，必须如实报出而不能误报成“公钥未生效”
                if($探测结果.免密输出 -match 'Corrupted MAC|message authentication code incorrect'){
                    Write-Warning '加密通道 MAC 校验失败：自动切换 AEAD 加密后仍无法避开，属于本机 OpenSSH 与该服务器的严重不兼容，无法判断公钥是否存在。请升级本机 OpenSSH 客户端，或联系服务器管理员检查 sshd 的加密配置。未进行任何移除操作。'
                    return
                }
                Write-Host '目标主机上本机公钥未生效（无法免密登录），无需移除。'
                return
            }
            Write-Verbose '免密登录成功，存在可移除的公钥。'

            # 免密登录已成功，检测平台后按真实平台移除（全程免密，不弹密码）
            $远程平台 = 获取远程平台
            Write-Verbose "远程平台检测结果: $远程平台"
            if($远程平台 -eq 'Windows'){
                $退出码 = 通过scp执行远程Windows脚本 $Windows脚本 $SSH参数 -远程用户 $RemoteUser -远程端口 $RemotePort -远程主机 $RemoteHost -加密附加参数 $加密附加参数
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