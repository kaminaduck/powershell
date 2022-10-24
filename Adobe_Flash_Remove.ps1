#requires -version 4
<#
.SYNOPSIS
  This is to automate the uninstall of Adobe Flash from Windows.
  This follows instructions taken from the following Adobe help article:
  https://helpx.adobe.com/flash-player/kb/uninstall-flash-player-windows.html

.DESCRIPTION
  This script runs the uninstaller, then checks if the hidden folders are present. 
  If the folders are present, they're deleted, otherwise, the script ends.

.INPUTS
  None

.OUTPUTS Log File
  The script log file stored in C:\Windows\Temp\Adobe_Flash_Remove.log

.NOTES
  AUTHOR				DATE			VERSION		DETAILS
  --------------------- --------------- ----------- --------------------------------
  Charlie Rogers		03.03.2020		00.00.01	Initial version
  Charlie Rogers		06.16.2020		00.00.02	Error in variable declaration fixed
  Charlie Rogers		06.16.2020		00.00.03	Commented out removing Desktop Experience. Caused a failure of updates on server.
  Charlie Rogers		06.16.2020		00.00.04	Added $Uninstaller_string to pass to Invoke-Expression
  													https://adamtheautomator.com/invoke-expression/ for reference
  Charlie Rogers        06.16.2020      00.00.05    Changed uninstaller to Start-Process, added 15-second pauses
  Charlie Rogers        10.24.2022      01.00.00    Changed format of file and standardized paths for general distribution.

  Future Improvements:
  - options for help, function descriptions
  - switches for just testing directories, isolating steps
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = 'SilentlyContinue'

#Import Modules & Snap-ins
Import-Module PSLogging

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = '01.00.00'

#Log File Info
$sLogPath = 'C:\Windows\Temp'
$sLogName = 'Adobe_Flash_Remove.log'
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

$Path_System32 = "C:\Windows\system32\Macromed"
$Path_SysWOW64 = "C:\Windows\SysWOW64\Macromed"
$Path_Uninstaller = ".\uninstall_flash_player.exe"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function DeleteAdobeFolder($arg1) {

    Begin {
        Write-LogInfo -LogPath $sLogFile -Message "`nDeleting $arg1 folder and contents..."
    }
    Process {
        Try {
            Write-LogInfo -LogPath $sLogFile -Message "`nTesting directory..."
            if ( ( Test-Path -Path $arg1 ) -eq 0) {
                Write-LogInfo -LogPath $sLogFile -Message "`nPath not found. Moving on..."
                break
            } else {
                Write-LogInfo -LogPath $sLogFile -Message "`nTaking ownership of folder..."
                takeown /F $arg1 /R /A 
                Write-LogInfo -LogPath $sLogFile -Message "`nGiving Admins full control of folder..."
                icacls $arg1 /T /grant administrators:F 
                Write-LogInfo -LogPath $sLogFile -Message "`nDeleting folder..."
                Remove-Item -path $arg1 -recurse -force
            }  
        }
    
        Catch {
          Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
          Break
        }
    }
    End {
        If ($?) {
          Write-LogInfo -LogPath $sLogFile -Message "`n$arg1 deleted successfully.`n"
        }
    }
}

Function RunUninstaller {
  
    Begin {
      Write-LogInfo -LogPath $sLogFile -Message "`nRunning Adobe Flash Uninstaller..."
    }
  
    Process {
        Try {
            if ( Test-Path -Path $Path_Uninstaller ) {
                Start-Process -FilePath "$Path_Uninstaller" -ArgumentList "-uninstall" -Verb RunAs -Wait
            } else {
                Write-LogInfo -LogPath $sLogFile -Message "`nUninstaller not found.`nPlease download the uninstaller from `nhttps://helpx.adobe.com/flash-player/kb/uninstall-flash-player-windows.html,`nplace in the C:\Distributions folder,`nand run this script again."
                exit 1
            }
        }
  
        Catch {
            Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
            Break
        }
    }
  
    End {
        If ($?) {
            Write-LogInfo -LogPath $sLogFile -Message "`nUninstalled successfully.`n"
        }
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion

RunUninstaller
Start-Sleep -s 15

DeleteAdobeFolder $Path_System32
Start-Sleep -s 15

DeleteAdobeFolder $Path_SysWOW64
Start-Sleep -s 15

Write-LogInfo -LogPath $sLogFile -Message "`nUninstallation complete."

Stop-Log -LogPath $sLogFile

