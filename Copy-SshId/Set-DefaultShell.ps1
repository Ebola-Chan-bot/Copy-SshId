# 在远程 Windows 主机把 OpenSSH 默认 shell 改为 PowerShell（幂等）
# 原理：OpenSSH for Windows 通过注册表 HKLM\SOFTWARE\OpenSSH\DefaultShell 决定登录 shell，
# 缺省为 cmd。这里把它固定指向系统自带的 Windows PowerShell 5.1。
# 输出单行状态标记供调用方判断；写 HKLM 需要管理员权限，失败时以 exit 5 返回，
# 由调用方按 best-effort 处理（只警告，不阻断密钥安装）。
$ErrorActionPreference = 'Stop'

$目标Shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$注册表路径 = 'HKLM:\SOFTWARE\OpenSSH'

# 已是 PowerShell 则无需改动（用文件名后缀匹配，兼容绝对路径写法差异）
$当前Shell = $null
try {
    $当前Shell = (Get-ItemProperty -Path $注册表路径 -Name DefaultShell -ErrorAction SilentlyContinue).DefaultShell
} catch { }
if($当前Shell -and ($当前Shell -match 'powershell\.exe$')) {
    Write-Output 'ALREADY_POWERSHELL'
    exit 0
}

try {
    New-Item -Path $注册表路径 -Force | Out-Null
    New-ItemProperty -Path $注册表路径 -Name DefaultShell -PropertyType String -Value $目标Shell -Force | Out-Null
    Write-Output 'SHELL_SET'
    exit 0
} catch {
    Write-Output "NO_PERMISSION: $($_.Exception.Message)"
    exit 5
}
