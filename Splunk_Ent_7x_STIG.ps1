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

# -----------------
# OS variables
# -----------------
$Computer = $env:COMPUTERNAME
$OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
# Gets network info such as IP addresses, gateways, DHCP status, etc, and saves as a tuple
$nwINFO = Get-WmiObject -ComputerName $Computer Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null } 
$nwServerName = $nwINFO.DNSHostName 
$nwDomain = $nwINFO.DNSDomain
$nwDescrip = $nwINFO.Description 
$nwIPADDR = $nwINFO.IPAddress 
$nwIPv4 = $( $nwIPADDR -split " ")[0]
$nwIPv6 = $( $nwIPADDR -split " ")[1]
$nwSUBNET = $nwINFO.IpSubnet 
$nwGateWay = $nwINFO.DefaultIPGateway 
$nwMACADD = $nwINFO.MACAddress 
$nwDNS = $nwINFO.DNSServerSearchOrder
$nwFQDN = "$nwServerName.$nwDomain"

# -----------------
# Line formatting variables
# -----------------
$LineDouble = "=============================================================================="
$LineSingle = "------------------------------------------------------------------------------"
$LineStars = "******************************************************************************"

# -----------------
# Date format variables
# -----------------
$CommonDate = $(Get-Date -UFormat "%m/%d/%Y")
$ScriptStart = $(Get-Date -Format yyyMMdd-HHmm)
$ReportDate = $(Get-Date -UFormat "%a %m/%d/%Y %T %Z")
$sStartDate = $(Get-Date -UFormat "%c")

# -----------------
# Variables for STIG checks
# -----------------
$Ent_Path = $null
$Ent_BIN_Path = "$Ent_Path\bin\"
$Auth_conf = "$Ent_Path\etc\system\local\authentication.conf"
$Web_conf = "$Ent_Path\etc\system\local\web.conf"
$Server_conf = "$Ent_Path\etc\system\local\server.conf"
$Health_conf = "$Ent_Path\etc\system\local\health.conf"
$Health_default = "$Ent_Path\etc\system\default\health.conf"
$Index_conf = "$Ent_Path\etc\system\local\indexes.conf"
$Inputs_Conf = "$Ent_Path\etc\system\local\inputs.conf"
$Outputs_Conf = "$Ent_Path\etc\system\local\outputsconf"
$LDAP_Conf = "$Ent_Path\etc\openldap\ldap.conf"
$UF_BIN_Path = $null
$UF_Output_Path = $null
$UF_Web_conf = $null
$Cluster_Index_conf = $null
$Cluster_Web_Conf = $null
$SH_Web_conf = $null

# -----------------
# V-221933 values to check
# -----------------
$input_ssl = "sslVersions = tls1.2"
$input_cipher = "cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
$input_ecdh = "ecdhCurves = prime256v1, secp384r1, secp521r1"
$output_ssl = "sslVersions = tls1.2"
$output_cipher = "cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
$output_ecdh = "ecdhCurves = prime256v1, secp384r1, secp521r1"
$server_ssl = "sslVersions = tls1.2"
$server_sslClient = "sslVersionsForClient = tls1.2"
$server_cipher = "cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES128-SHA256"
$server_ecdh = "ecdhCurves = prime256v1, secp384r1, secp521r1"
$web_ssl = "sslVersions = tls1.2"
$web_cipher = "cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
$web_ecdh = "ecdhCurves = prime256v1, secp384r1, secp521r1"
$ldap_tlsComment = "# TLS_PROTOCOL_MIN: 3.1 for TLSv1.0, 3.2 for TLSv1.1, 3.3 for TLSv1.2."
$ldap_tls = "TLS_PROTOCOL_MIN 3.3"
$ldap_cipher = "TLS_CIPHER_SUITE ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"

# -----------------
# Variables for checking Apache installation status
# -----------------
$ServiceName = $null
$ApacheStart = $null
$ApacheStartName = $null
$ApacheStatus = $null
$ApacheExists = $null
$WebExists = $null
$WebStatus = $null
$ServerRole = $null

# -----------------
# Variables for STIG findings report
# -----------------
[int]$CAT1_PASS=0; [int]$CAT1_OPEN=0; [int]$CAT1_NA=0; [int]$CAT1_NR=0 
[int]$CAT2_PASS=0; [int]$CAT2_OPEN=0; [int]$CAT2_NA=0; [int]$CAT2_NR=0 
[int]$CAT3_PASS=0; [int]$CAT3_OPEN=0; [int]$CAT3_NA=0; [int]$CAT3_NR=0 
$STIG_CCI = $null     
$STIG_Response = $null 
$STIG_Rule_ID = $null     
$STIG_Severity = $null     # Values: (I, II, or III)
$STIG_ID = $null     
$STIG_Check_Status = $null   # Values: (OPEN, PASS, NA, NR)
$NIST_CM = $null    # NIST SP 800-53r4 CM category.
[int]$STIG_Count = 0     
$STIG_Vuln_ID = $null      
[int]$STIG_Count_NA = 0 
[int]$STIG_Count_NR = 0     
[int]$STIG_Count_OPEN = 0     
[int]$STIG_Count_PASS = 0   


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