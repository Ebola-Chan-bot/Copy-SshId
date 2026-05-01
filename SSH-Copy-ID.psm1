function ssh-copy-id
{
<#
.SYNOPSIS
    Appends a public key to a machines ~/.ssh/authorized_keys file.
    Existing keys are skipped instead of being appended again.

.DESCRIPTION
    ssh-copy-id is a PowerShell script that uses ssh to log into a remote machine and append the
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

    PS> ssh-copy-id root@172.16.1.10

.EXAMPLE

    PS> ssh-copy-id 172.16.1.10 -l root

.EXAMPLE

    PS> ssh-copy-id 172.16.1.10 -p 2222

.EXAMPLE

    PS> ssh-copy-id root@172.16.1.10 -i C:\users\n8tg\SpecialKeyDir\key.pub

.EXAMPLE

    PS> ssh-copy-id -RemoteHost 172.16.1.10 -RemoteUser root

.EXAMPLE

    PS> ssh-copy-id -RemoteHost 172.16.1.10 -RemoteUser root -KeyFile C:\users\n8tg\SpecialKeyDir\key.pub

.NOTES

    If no username is supplied using -RemoteUser or the User@RemoteHost syntax, the user running the command's username will be used.

.LINK

https://github.com/n8tg/ssh-copy-id
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

        $windowsScript = @'
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
        [System.IO.File]::AppendAllText($authorizedKeys, [Environment]::NewLine, [System.Text.Encoding]::ASCII)
    }

    $existingKeys = @(Get-Content -LiteralPath $authorizedKeys -ErrorAction SilentlyContinue)
}

foreach ($keyLine in $keyLines) {
    if ($existingKeys -notcontains $keyLine) {
        [System.IO.File]::AppendAllText($authorizedKeys, $keyLine + [Environment]::NewLine, [System.Text.Encoding]::ASCII)
        $existingKeys += $keyLine
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
'@
        $windowsScript = $windowsScript.Replace('__ENCODED_KEY_TEXT__', $encodedKeyText)
        $windowsScriptBytes = [Text.Encoding]::UTF8.GetBytes($windowsScript)
        $compressedWindowsScriptStream = New-Object IO.MemoryStream
        $gzipStream = New-Object IO.Compression.GzipStream -ArgumentList $compressedWindowsScriptStream, ([IO.Compression.CompressionMode]::Compress)
        $gzipStream.Write($windowsScriptBytes, 0, $windowsScriptBytes.Length)
        $gzipStream.Dispose()
        $compressedWindowsScript = [Convert]::ToBase64String($compressedWindowsScriptStream.ToArray())

        $windowsDecoderScript = @"
`$compressedWindowsScript = '$compressedWindowsScript'
`$compressedWindowsScriptBytes = [Convert]::FromBase64String(`$compressedWindowsScript)
`$compressedWindowsScriptStream = New-Object IO.MemoryStream -ArgumentList (, `$compressedWindowsScriptBytes)
`$gzipStream = New-Object IO.Compression.GzipStream -ArgumentList `$compressedWindowsScriptStream, ([IO.Compression.CompressionMode]::Decompress)
`$reader = New-Object IO.StreamReader -ArgumentList `$gzipStream, ([Text.Encoding]::UTF8)
Invoke-Expression `$reader.ReadToEnd()
"@
        $encodedWindowsScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($windowsDecoderScript))
        $windowsCommand = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedWindowsScript"

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
                $exitCode = Invoke-KeyInstallCommand -Command $windowsCommand
            }else{
                $exitCode = Invoke-KeyInstallCommand -Command $unixCommand -PipeKey
                if($exitCode -ne 0){
                    Write-Verbose "Unix install command failed. Trying Windows install command."
                    $exitCode = Invoke-KeyInstallCommand -Command $windowsCommand
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

Export-ModuleMember -Function ssh-copy-id