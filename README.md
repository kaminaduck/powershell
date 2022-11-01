# powershell
 A repo of all powershell scripts I've written. These can be used independently of each other.

# Adobe_Flash_Remove.ps1
This is a script I wrote to automate the folder deletion. I wrote it because I had to remove Adobe Flash off of 50ish servers, and I didn't want to do it manually.

This script is written to be run in the same directory as the Adobe uninstaller. Find it at https://helpx.adobe.com/flash-player/kb/uninstall-flash-player-windows.html

# Splunk_Ent_7x_STIG.ps1 (in progress)
This script took a lot of repetitive work off of my hands. A colleague of mine did something similar with Windows Server 2012 R2, and I used that as a frame for this script, which is why it's still in progress. I am currently updating it to be self-sufficient, while learning best practices. Most of the automation in this is checking values in .conf files with established baseline configurations. I will attempt to keep this updated as time allows, but most of the work on this lately has been to make it useable in any Windows environment with PowerShell 7.2. I understand that this will be less and less useful as Splunk Enterprise continues to update, but it's still nice to show the work I did for this.

This is not compatible with the Evaluate-STIG tool. 

The STIG info is taken from https://public.cyber.mil/stigs/downloads/