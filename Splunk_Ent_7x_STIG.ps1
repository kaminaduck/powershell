#requires -version 4
<#
.SYNOPSIS
  This runs all checks in the Splunk Enterprise 7.x for Windows Security Technical Implementation Guide

.DESCRIPTION
  This script will automate all checks that are or can be found in .conf files, and there will be boilerplate answers on checks
  that require qualitative answers.

.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
  <Inputs if any, otherwise state None>

.OUTPUTS 
  The script log file is stored in C:\Script_Outputs\Splunk_Ent_7x_STIG.log
  The script output file is stored in C:\Script_Outputs\Splunk_Ent_7x_STIG.txt

.NOTES
  Version:        00.00.01
  Author:         Charlie Rogers
  Creation Date:  10/25/2002
  Purpose/Change: Initial script development to be universally deployable

#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

Param (
  #Script parameters go here
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#Import Modules & Snap-ins
Import-Module PSLogging

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "00.00.01"

#Log File Info
$sLogPath = "C:\Script_Outputs"
$sLogName = "Splunk_Ent_7x_STIG.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#-----------------------------------------------------------[Functions]------------------------------------------------------------

<#

Function <FunctionName> {
  Param ()

  Begin {
    Write-LogInfo -LogPath $sLogFile -Message "<description of what is going on>..."
  }

  Process {
    Try {
      <code goes here>
    }

    Catch {
      Write-LogError -LogPath $sLogFile -Message $_.Exception -ExitGracefully
      Break
    }
  }

  End {
    If ($?) {
      Write-LogInfo -LogPath $sLogFile -Message "Completed Successfully."
      Write-LogInfo -LogPath $sLogFile -Message " "
    }
  }
}

#>

Function TestLogPath {
<#
Checks to see if the log path exists. 
If it does, the function delets all files out of the path.
If it does not, the function creates the directory.
#>
  
    Process {
      Try {
        If ( test-path "$sLogPath" ) { 
            Remove-Item $sLogPath\*.* -Force
        }
        Else { 
            New-Item -ItemType Directory -Force -Path $sLogPath 
        }
      }
  
      Catch {
        Write-Output "`n$sLogPath unable to be created." -Message $_.Exception -ExitGracefully
        Break
      }
    }
  
    End {
      If ($?) {
        Write-LogInfo -LogPath $sLogFile -Message "`nLog directory and file completed successfully."
      }
    }
  }

#-----------------------------------------------------------[Execution]------------------------------------------------------------
TestLogPath
Start-Log -LogPath $sLogPath -LogName $sLogName -ScriptVersion $sScriptVersion
#Script Execution goes here
Stop-Log -LogPath $sLogFile