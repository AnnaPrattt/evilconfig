
![image](header.jpg)

**EVILCONFIG** - A PowerShell script to quickly weaken a Windows device, with optional persistence.


## Purpose

This script can be used after initial exploitation, allowing an attacker to quickly weaken the device to assist in further exploitation, privilege escalation, or lateral movement. Defenders may find value in using this script to test their local security policies or domain group policies. 

## Requirements
This script requires a stable internet connection.

## Features
The current version of **EvilConfig v1.0** contains these features. Persistence can be optionally added with the `--persist` flag.

### Defense Evasion

* Disable Windows Event Logging
* Disable Firewall logging
* Disable Windows Defender
* Disable Windows Firewall (Public)
* Disable Windows Firewall (Domain)
* Disable Windows Firewall (Private)

### Weakening/Vulnerabilities

* Enable local Administrator account
* Enable local Guest account
* Disable User Access Control (UAC)
* Enable Wdigest registry key
* Disable local password policy
* Disable local account lockouts
* Enable SMBv1
* Disable Windows Updates
* Disable Secure Boot
* Disable Smart Screen
* Disable BitLocker
* Disable Tamper Protection
* Set PowerShell execution policy to Unrestricted


### Persistence
This persistence module is optional and can be run with the `--persist` flag.

* Install SSH client
* Install TeamViewer
* Add local user (non-privileged)
* Add local user (privileged)
* Add local user to RDP group

## Disclaimer

This tool may break things. This tool should only be executed on devices on which you have authorized permission to perform malicious actions. If using this tool in a contracted offensive engagement, review your scoping agreement and rules-of-engagement for an appropriate service downtime clause before using this tool. 