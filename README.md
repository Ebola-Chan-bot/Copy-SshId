This is a lame PowerShell implementation of OpenSSH's Copy-SshId.

`Copy-SshId` is a PowerShell function that uses ssh to log into a remote machine and append missing keys from the
indicated identity file to that machine's `~/.ssh/authorized_keys` file. By default, it installs the key(s) stored in `$env:USERPROFILE\.ssh\id_rsa.pub`.

Existing keys are skipped instead of being appended again.

---

# Installation

This is published as a module in the PowerShell Gallery.

## Installing Copy-SshId the easy way

    Install-Module -Name Copy-SshId

## Getting access to the PowerShell Gallery

See: <https://docs.microsoft.com/en-us/powershell/scripting/gallery/overview?view=powershell-7.1>

    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name PowerShellGet -Force

---

# Usage

## Parameters (PS Style)

Param | Mandatory | Default | Description
------|-----------|---------|------------
RemoteHost | Yes | (none) | Specifies the IP or DNS name of the machine to install the public key on.
RemoteUser | No |(none) | Specifies which user's authorized_keys file that the key will be installed under.
KeyFile | No | "$env:USERPROFILE\.ssh\id_rsa.pub" | A path of the keyfile to be installed. If the default file is missing, common public key names in `$env:USERPROFILE\.ssh` are searched automatically. If no key exists at all, a new `ed25519` key pair is generated automatically (passphrase-less) before installation.
RemotePort | No | 22 | SSH will attempt to connect to this port on the remote host.

## Parameters (Unix Style)

Param | Mandatory | Default | Description
------|-----------|---------|------------
$RemoteHost (Positional Parameter) | Yes | (none) | Specifies the IP or DNS name of the machine to install the public key on. Used without referencing a parameter flag.
-l | No |(none) | Specifies which user's authorized_keys file that the key will be installed under.
-i | No | "$env:USERPROFILE\.ssh\id_rsa.pub" | A path of the keyfile to be installed. If the default file is missing, common public key names in `$env:USERPROFILE\.ssh` are searched automatically.
-p | No | 22 | SSH will attempt to connect to this port on the remote host.

---

# Examples

## Unix username style

    Copy-SshId root@172.16.1.10 
    Copy-SshId 172.16.1.10 -l root 

## Unix username style with a specified key file

    Copy-SshId root@172.16.1.10 -i C:\users\n8tg\SpecialKeyDir\key.pub

## PowerShell parameter style with a username

    Copy-SshId -RemoteHost 172.16.1.10 -RemoteUser root  

## PowerShell parameter style with a username and a specific key

    Copy-SshId -RemoteHost 172.16.1.10 -RemoteUser root -KeyFile C:\users\n8tg\SpecialKeyDir\key.pub

## Windows OpenSSH server

    Copy-SshId -RemoteHost windows.example.com -RemoteUser user

The remote platform is detected automatically. On Windows targets, Copy-SshId reads `C:\ProgramData\ssh\sshd_config` and installs the key into the first applicable `AuthorizedKeysFile`, including settings under `Match Group administrators`.

## You can mix and match if you choose

    Copy-SshId -RemoteHost root@172.16.1.10 -i c:\why\key.pub

---

# Remove-SshId — 移除免密登录

`Remove-SshId` 通过 SSH 登录远程主机，从指定用户的 `authorized_keys` 文件中删除本机公钥。
删除后，该远程主机将不再接受本机的免密登录，恢复为需要密码认证的状态。

## 参数

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| RemoteHost | 是 | (无) | 目标主机的 IP 地址或 DNS 名称 |
| RemoteUser | 否 | (无) | 目标主机上要移除免密登录许可的用户名 |
| KeyFile | 否 | `$env:USERPROFILE\.ssh\id_rsa.pub` | 要移除的密钥文件路径 |
| RemotePort | 否 | 22 | SSH 连接端口 |

也支持 `-l`、`-i`、`-p` 别名和 `User@Host` 语法。

## 示例

### 移除 root 用户的免密登录

    Remove-SshId root@172.16.1.10

### 指定用户名和端口

    Remove-SshId 192.168.1.100 -l admin -p 2222

### 指定要移除的密钥文件

    Remove-SshId -RemoteHost server.example.com -RemoteUser deploy -KeyFile C:\keys\deploy.pub

### 移除 Windows OpenSSH 服务器上的免密登录

    Remove-SshId -RemoteHost windows.example.com -RemoteUser user

目标平台会被自动检测：Unix 下直接操作 `~/.ssh/authorized_keys`，Windows 下读取 `C:\ProgramData\ssh\sshd_config` 定位 `AuthorizedKeysFile` 并移除对应密钥。
