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


#----------------------------------------------------------[Declarations]----------------------------------------------------------

# Script Version
$sScriptVersion = "00.00.01"

# File Info
$sLogPath = "C:\Script_Outputs"
$sLogName = "Splunk_Ent_7x_STIG.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName
$sOutputTxtName = "Splunk_Ent_7x_STIG.txt"
$sOutputTxtFile = Join-Path -Path $sLogPath -ChildPath $sOutputTxtName
$sOutputCSVName = "Splunk_Ent_7x_STIG.csv"
$sOutputCSVFile = Join-Path -Path $sLogPath -ChildPath $sOutputCSVName

# Script Info
$MyHashValue = $($(Get-FileHash $PSCommandPath -Algorithm SHA256).Hash)

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
$UF_Web_conf = $null    # This variable is in case your server has a Universal Forwarder installed; the default install directory is different for UFs than Enterprise.
$Cluster_Index_conf = $null
$Cluster_Web_Conf = $null   # This variable is in case your environment's indexers are clustered, which should be in /etc/peer-apps/ somewhere
$SH_Web_conf = $null    # This variable is in case your environment's saved the Search Head web.conf file in a location other than /etc/system/local/

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
[int]$CAT1_TOTAL=0;[int]$CAT1_PASS=0; [int]$CAT1_OPEN=0; [int]$CAT1_NA=0; [int]$CAT1_NR=0 
[int]$CAT2_TOTAL=0;[int]$CAT2_PASS=0; [int]$CAT2_OPEN=0; [int]$CAT2_NA=0; [int]$CAT2_NR=0 
[int]$CAT3_TOTAL=0;[int]$CAT3_PASS=0; [int]$CAT3_OPEN=0; [int]$CAT3_NA=0; [int]$CAT3_NR=0 
$STIG_Title = $null
$STIG_CCI = $null     
$STIG_Response = $null 
$STIG_Rule_ID = $null     
$STIG_Severity = $null     # Values: (I, II, or III)
$STIG_ID = $null     
$STIG_Check_Status = $null   # Values: (OPEN, PASS, NA, NR)
$NIST_CM = $null    # NIST SP 800-53r4 CM category.
$STIG_Vuln_ID = $null      
[int]$STIG_Count = 0 
[int]$STIG_Count_NA = 0 
[int]$STIG_Count_NR = 0     
[int]$STIG_Count_OPEN = 0     
[int]$STIG_Count_PASS = 0



#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function TestLogPath {
<#
Checks to see if the log path exists. 
If it does, the function delets all files out of the path.
If it does not, the function creates the directory.
#>
  
    Process {
      Try {
        If ( Test-Path "$sLogPath" ) { 
            Remove-Item $sLogPath\*.* -Force
        }
        Else { 
            New-Item -Path $sLogPath -ItemType "Directory" -Force 
        }
      }
  
      Catch {
        Write-Output "`n$sLogPath unable to be created." -Message $_.Exception -ExitGracefully
        Break
      }
    }
}

Function CheckForApache {
<#
This function will have nested try/catch statements because I'm trying to allow for any eventuality of Apache installation.
I'm sure there's a better way to handle it, but I'm not sure of one yet.
Also I'm not sure if this function works yet.
#>
    Begin {
        Add-Content -Path $sLogFile -Value "`nChecking status of Apache installation"
        $ServiceName = Read-Host -Prompt "`nPlease input the name of the Apache HTTPD service installed: "
    }
    
    Process {
        Try {
            Try { 
                $ApacheStart = (Get-Service $ServiceName).StartType 
            } 
            catch { 
                $ApacheExists="NO" 
            } 
            Try { 
                $ApacheStartName = (Get-WmiObject Win32_Service -Filter "Name='$ServiceName'").StartName 
            } 
            catch { 
                $ApacheStartName = $null 
            }
            Try { 
                $ApacheStatus = (Get-Service $ServiceName).Status 
            } 
            catch {
                $ApacheStatus = "NA" 
            } 
            switch ($ApacheStart) { # Acceptable values of the start type for the service to exist
                "Automatic" { $ApacheExists="YES" }
                "Manual" { $ApacheExists="YES" }
                "Disabled" { $ApacheExists="YES" }
            }
        }
    
        Catch {
            Add-Content -Path $sLogFile -Value $_.Exception 
          Break
        }
    }
    
    End {
        If ($?) {
            Add-Content -Path $sLogFile -Value "`nApache existence check completed successfully."
        }
    }
}

Function CheckServerRole {
<#
This function checks to see if the Splunk installation is a search head, an indexer, or a universal forwarder.
This is based on the assumption that Splunk is installed in the first place.
#>
    Begin {
        Add-Content -Path $sLogFile -Value "`nChecking Splunk Enterprise server role..."
        CheckForApache
    }
    
    Process {
        Try {
            if ( $ApacheExists -eq "YES" ) {
                $ServerRole = "WEB"
            }
            else {
                if ( Test-Path $Cluster_Index_conf ) {
                    $ServerRole = "INDEXER"
                }
                else {
                    $ServerRole = "FORWARDER"
                }
            }
        }
    
        Catch {
            Add-Content -Path $sLogFile -Value $_.Exception 
          Break
        }
    }

    End {
        If ($?) {
            Add-Content -Path $sLogFile -Value "`nSplunk Enterprise server role check completed successfully."
        }
    }
}

Function CheckForWeb {
<#
This function checks to see if the Splunk installation has a web interface enabled, based upon its installation.
Search heads should have a web interface, while indexers and universal forwarders should not.
#>
    Begin {
        Add-Content -Path $sLogFile -Value "`nChecking Splunk Enterprise web interface status..."
        CheckServerRole
        # temporary string placeholders
        [string]$data = $null
        [string]$data1 = $null
        $data = Get-Content $Web_conf | Select-String -NotMatch "#" | Select-String -Pattern startwebserver
    }

    Process {
        Try {
            if ( $ServerRole -eq "WEB" ) {
                $data1 = Get-Content $SH_Web_conf | Select-String -NotMatch "#" | Select-String -Pattern startwebserver
                if ( ($data -eq "startwebserver = 1") -or ($data1 -eq "startwebserver = 1" ) ) { 
                    $WebExists = "YES" 
                }
                elseif ( ($data -eq "startwebserver = 0") -or ($data1 -eq "startwebserver = 0") ) {
                    $WebExists = "NO"
                }
                else {
                    $WebExists = "UNKNOWN"
                }
            }
            elseif ( $ServerRole -eq "INDEXER" ) {
                $data1 = Get-Content $Cluster_Web_Conf | Select-String -NotMatch "#" | Select-String -Pattern startwebserver
                if ( ($data -eq "startwebserver = 1") -or ($data1 -eq "startwebserver = 1" ) ) { 
                    $WebExists = "YES" 
                }
                elseif ( ($data -eq "startwebserver = 0") -or ($data1 -eq "startwebserver = 0") ) {
                    $WebExists = "NO"
                }
                else {
                    $WebExists = "UNKNOWN"
                }
            }
            elseif ( $ServerRole -eq "FORWARDER" ) {
                $data1 = Get-Content $UF_Web_conf | Select-String -NotMatch "#" | Select-String -Pattern startwebserver
                if ( ($data -eq "startwebserver = 1") -or ($data1 -eq "startwebserver = 1" ) ) { 
                    $WebExists = "YES" 
                }
                elseif ( ($data -eq "startwebserver = 0") -or ($data1 -eq "startwebserver = 0") ) {
                    $WebExists = "NO"
                }
                else {
                    $WebExists = "UNKNOWN"
                }
            }
            else {
                $WebExists = "ERROR"
            }
        }
    
        Catch {
            Add-Content -Path $sLogFile -Value $_.Exception 
          Break
        }
    }
    
    End {
        If ($?) {
            Add-Content -Path $sLogFile -Value "`nSplunk Enterprise web interface check completed successfully."
        }
    }
}

Function ScriptFilesList {
    Write-Output "`nScript Hash: $MyHashValue"

}

# =============================================================================== 
# Function to update output file
# =============================================================================== 
Function UpdateReport {
    
    Begin {
        Add-Content -Path $sLogFile -Value "`nUpdating STIG report..."
        Add-Content -Path $sOutputCSVFile -Value "$Computer,$nwIPv4,$nwMACADD,V-$STIG_Vuln_ID,$STIG_Check_Status,$STIG_Severity,SV-$STIG_Rule_ID,$STIG_ID,$NIST_CM,$STIG_CCI,$STIG_Title"
    }
    
    Process {
        Try {
            $STIG_Count++
            switch ($STIG_Check_Status) {
                "OPEN" { $STIG_Count_OPEN++ }
                "NA" { $STIG_Count_NA++ }
                "NR" { $STIG_Count_NR++ }
                default { $STIG_Count_PASS++ }
            }
            switch ($STIG_Severity) {
                "I" { switch ($STIG_Check_Status) {
                        "OPEN" { $CAT1_TOTAL++; $CAT1_OPEN++ }
                        "NA" { $CAT1_TOTAL++; $CAT1_NA++ }
                        "NR" { $CAT1_TOTAL++; $CAT1_NR++ }
                        default { $CAT1_TOTAL++; $CAT1_PASS++}
                    }; break
                }
                "II" { switch ($STIG_Check_Status) {
                        "OPEN" { $CAT2_TOTAL++; $CAT2_OPEN++ }
                        "NA" { $CAT2_TOTAL++; $CAT2_NA++ }
                        "NR" { $CAT2_TOTAL++; $CAT2_NR++ }
                        default { $CAT2_TOTAL++; $CAT2_PASS++}
                    }; break
                }
                "III" { switch ($STIG_Check_Status) {
                        "OPEN" { $CAT3_TOTAL++; $CAT3_OPEN++ }
                        "NA" { $CAT3_TOTAL++; $CAT3_NA++ }
                        "NR" { $CAT3_TOTAL++; $CAT3_NR++ }
                        default { $CAT3_TOTAL++; $CAT3_PASS++}
                    }; break
                }
            }     
        }
    
        Catch {
            Add-Content -Path $sLogFile -Value $_.Exception 
          Break
        }
    }

    End {
        If ($?) {
            Add-Content -Path $sLogFile -Value "`nSTIG Report Updated Successfully."
        }
    }


}

Function FLines { 
    Param (
        [Parameter(Mandatory=$true,Position=0)][string]$Location,
        [Parameter(Mandatory=$false,Position=1)][int]$NumLines
    )

    Begin {
        Add-Content -Path $sLogFile -Value "`nPrinting lines..."
    }

    Process {
        Try {
            switch ($Location) {
                $sLogFile {
                    switch ($NumLines) { 
                        0 { Add-Content -Path $sLogFile -Value " " } 
                        1 { Add-Content -Path $sLogFile -Value "`n$LineSingle" } 
                        2 { Add-Content -Path $sLogFile -Value "`n$LineDouble" } 
                        3 { Add-Content -Path $sLogFile -Value "`n$lineStars" } 
                        4 { Add-Content -Path $sLogFile -Value "`n$LineSingle`n$LineDouble`n$lineStars" }
                        default { Add-Content -Path $sLogFile -Value "`n$LineDouble" } 
                    }         
                }
                $sOutputTxtFile {
                    switch ($NumLines) { 
                        0 { Add-Content -Path $sOutputTxtFile -Value " " } 
                        1 { Add-Content -Path $sOutputTxtFile -Value "`n$LineSingle" } 
                        2 { Add-Content -Path $sOutputTxtFile -Value "`n$LineDouble" } 
                        3 { Add-Content -Path $sOutputTxtFile -Value "`n$lineStars" } 
                        4 { Add-Content -Path $sOutputTxtFile -Value "`n$LineSingle`n$LineDouble`n$lineStars" }
                        default { Add-Content -Path $sOutputTxtFile -Value "`n$LineDouble" } 
                    }         
                }
                $sOutputCSVFile {
                    switch ($NumLines) { 
                        0 { Add-Content -Path $sOutputCSVFile -Value " " } 
                        1 { Add-Content -Path $sOutputCSVFile -Value "`n$LineSingle" } 
                        2 { Add-Content -Path $sOutputCSVFile -Value "`n$LineDouble" } 
                        3 { Add-Content -Path $sOutputCSVFile -Value "`n$lineStars" } 
                        4 { Add-Content -Path $sOutputCSVFile -Value "`n$LineSingle`n$LineDouble`n$lineStars" }
                        default { Add-Content -Path $sOutputCSVFile -Value "`n$LineDouble" } 
                    }         
                }
            }
        }
    
        Catch {
            Add-Content -Path $sLogFile -Value $_.Exception 
          Break
        }
    }

    End {
        If ($?) {
            Add-Content -Path $sLogFile -Value "`nLines printed successfully."
        }
    }
}

# ==================================================================================
# Splunk STIG checks
# ==================================================================================

# ------------------------------------------------------------------------------
# Splunk Enterprise must be installed with FIPS mode enabled, to implement NIST FIPS 140-2 approved ciphers for all cryptographic functions.
# Splunk Enterprise 7.x for Windows Vul ID: V-221600 Rule ID: SV-221600r508660_rule	 STIG ID: SPLK-CL-000010
# ------------------------------------------------------------------------------
Function CheckV221600 {
    Param ()

    Begin {
      Add-Content -Path $sLogFile -Value "`nChecking V-$STIG_Vuln_ID..."
      FLines $sOutputTxtFile 1 
      Add-Content -Path $sOutputTxtFile -Value "`nV-$STIG_Vuln_ID SV-$STIG_Rule_ID $STIG_ID `nNIST SP 800-53 Revision 4: $NIST_CM $STIG_CCI Cat-$STIG_Severity `n  - $STIG_Title"
      FLines $sOutputTxtFile 1 
    }
  
    Process {
      Try {
        $STIG_Response = "Execute a search query using the following:`n| rest splunk_server=local /services/server/info | fields fips_mode`nVerify that the report returns fips_mode = 1" 
        $STIG_Check_Status = "OPEN"
      }
  
      Catch {
        Add-Content -Path $sLogFile -Value $_.Exception 
        Break
      }
    }
  
    End {
      If ($?) {
        Add-Content -Path $sOutputTxtFile -Value "`nStatus: $STIG_Check_Status`nResponse: $STIG_Response"
        Add-Content -Path $sLogFile -Value "`nV-$STIG_Vuln_ID Completed Successfully."
        UpdateReport
      }
    }
}

# ------------------------------------------------------------------------------
# Splunk Enterprise must use organization level authentication to uniquely identify and authenticate users.
# Splunk Enterprise 7.x for Windows Vul ID: V-221601 Rule ID: SV-221601r508660_rule STIG ID: SPLK-CL-000020
# ------------------------------------------------------------------------------
Function CheckV221601 {
    Param ()

    Begin {
      Add-Content -Path $sLogFile -Value "`nChecking V-$STIG_Vuln_ID..."
      FLines $sOutputTxtFile 1 
      Add-Content -Path $sOutputTxtFile -Value "`nV-$STIG_Vuln_ID SV-$STIG_Rule_ID $STIG_ID `nNIST SP 800-53 Revision 4: $NIST_CM $STIG_CCI Cat-$STIG_Severity `n  - $STIG_Title"
      FLines $sOutputTxtFile 1 
    }    
    
    Process {
        Try {
            [string]$data = $null
            $data = Get-Content $Auth_conf | Select-String -Pattern authType
            if ( $data -eq "authType = LDAP" )  {
                $STIG_Response = "LDAP authentication method is selected: $data" 
                $STIG_Check_Status = "PASS"
            }
            elseif ( $data -eq "authType = SAML" ) {
                $STIG_Response = "SAML authentication method is selected: $data" 
                $STIG_Check_Status = "PASS"
            }
            else {
                $STIG_Response = "LDAP or SAML is not selected: $data"
                $STIG_Check_Status = "OPEN"
            }
        }
    
        Catch {
            Add-Content -Path $sLogFile -Value $_.Exception 
            Break
        }
    } 
    
    End {
        If ($?) {
          Add-Content -Path $sOutputTxtFile -Value "`nStatus: $STIG_Check_Status`nResponse: $STIG_Response"
          Add-Content -Path $sLogFile -Value "`nV-$STIG_Vuln_ID Completed Successfully."
          UpdateReport
        }
      }
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------
cls
TestLogPath
New-Item -Path $sLogPath -Name $sLogName -ItemType "File" 
Add-Content -Path $sLogFile -Value "`nUser: $env:USERNAME`n`tHost: $Computer`nDirectory: $([char]34)$pwd$([char]34)."
Add-Content -Path $sLogFile -Value "`nStart Collecting OS information: $($(Get-Date).ToString("u"))"




#Script Execution goes here
Stop-Transcript





DocumentMarking 1 > $Tmpfile0
ScriptHeader 2 >> $Tmpfile0
FLines 0 >> $Tmpfile0
FLines 2 >> $Tmpfile0
HardwareAndOSInformation >> $Tmpfile0
FLines 2 >> $Tmpfile0

cat $Tmpfile0 > $WorkingTXTFile
cat $Tmpfile0 > $ArchiveOpenTXTFile
cat $Tmpfile0 > $EmailTextFile

switch ($ScreenOutput) {
    1 { cat $script:WorkingTXTFile }
}

Write-output "Starting Splunk Enterprise Checks: $($(Get-Date).ToString("u"))"
Write-output "Starting Splunk Enterprise Checks: $($(Get-Date).ToString("u"))" >> $ScriptLog
Write-output "Starting Splunk Enterprise Checks: $($(Get-Date).ToString("u"))" >> $WorkingTXTFile
Write-output "Starting Splunk Enterprise Checks: $($(Get-Date).ToString("u"))" >> $ArchiveOpenTXTFile


# ------------------------------------------------------------------------------
# Write the column headers to the CSV file used to capture the Manual SCAP results from this script.
# ------------------------------------------------------------------------------
Write-Output "Computer,IP Address,MAC Address,Vuln-ID,Date Checked,Status,Severity,Rule ID,STIG ID,SP800-53r4 Category,CCI References,SCAP Title,SCAP Release ID,Script Name,Script Version" > $script:WorkingCSVFile

$scapTITLE="Splunk Enterprise 7.x for Windows STIG"; $SCAPReleaseID="v2r1";
$scapSTIGS++; $scapVID="221600"; $scapRID="221600r508660_rule"; $Ver2=1; $scapSID="000010"; $SP80053r4="SC-13"; $scapCCI="CCI-002450"; $scapSEV="I"; $scapRuleTITLE="Splunk Enterprise must be installed with FIPS mode enabled, to implement NIST FIPS 140-2 approved ciphers for all cryptographic functions."; CheckV221600; 
$scapSTIGS++; $scapVID="221601"; $scapRID="221601r508660_rule"; $Ver2=1; $scapSID="000020"; $SP80053r4="IA-2"; $scapCCI="CCI-000764"; $scapSEV="I"; $scapRuleTITLE="Splunk Enterprise must use organization level authentication to uniquely identify and authenticate users."; CheckV221601; 
$scapSTIGS++; $scapVID="221602"; $scapRID="221602r508660_rule"; $Ver2=1; $scapSID="000030"; $SP80053r4="IA-2"; $scapCCI="CCI-000764"; $scapSEV="I"; $scapRuleTITLE="Splunk Enterprise must have all local user accounts removed after implementing organizational level user management system, except for one emergency account of last resort."; CheckV221602; 
$scapSTIGS++; $scapVID="221605"; $scapRID="221605r508660_rule"; $Ver2=1; $scapSID="000045"; $SP80053r4="IA-2"; $scapCCI="CCI-001953"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must use an SSO proxy service, F5 device, or SAML implementation to accept the DoD CAC or other smart card credential for identity management, personal authentication, and multifactor authentication."; CheckV221605; 
$scapSTIGS++; $scapVID="221607"; $scapRID="221607r508660_rule"; $Ver2=1; $scapSID="000060"; $SP80053r4="IA-2"; $scapCCI="CCI-001941"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must use HTTPS/SSL for access to the user interface."; CheckV221607; 
$scapSTIGS++; $scapVID="221608"; $scapRID="221608r508660_rule"; $Ver2=1; $scapSID="000070"; $SP80053r4="SC-8"; $scapCCI="CCI-002418"; $scapSEV="I"; $scapRuleTITLE="Splunk Enterprise must use SSL to protect the confidentiality and integrity of transmitted information."; CheckV221608; 
$scapSTIGS++; $scapVID="221609"; $scapRID="221609r508660_rule"; $Ver2=1; $scapSID="000080"; $SP80053r4="IA-5"; $scapCCI="CCI-000197"; $scapSEV="I"; $scapRuleTITLE="Splunk Enterprise must use LDAPS for the LDAP connection."; CheckV221609; 
$scapSTIGS++; $scapVID="221612"; $scapRID="221612r508660_rule"; $Ver2=1; $scapSID="000105"; $SP80053r4="AU-9(2)"; $scapCCI="CCI-001348"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must be configured to back up the log records repository at least every seven days onto a different system or system component other than the system or component being audited."; CheckV221612; 
$scapSTIGS++; $scapVID="221613"; $scapRID="221613r508660_rule"; $Ver2=1; $scapSID="000160"; $SP80053r4="AU-10"; $scapCCI="CCI-000166"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must be configured to protect the log data stored in the indexes from alteration."; CheckV221613; 
$scapSTIGS++; $scapVID="221614"; $scapRID="221614r508660_rule"; $Ver2=1; $scapSID="000170"; $SP80053r4="CM-6(b)"; $scapCCI="CCI-000366"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must use TCP for data transmission."; CheckV221614; 
$scapSTIGS++; $scapVID="221621"; $scapRID="221621r508660_rule"; $Ver2=1; $scapSID="000250"; $SP80053r4="AU-12(1)"; $scapCCI="CCI-000174"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must be configured to aggregate log records from organization-defined devices and hosts within its scope of coverage."; CheckV221621; 
$scapSTIGS++; $scapVID="221622"; $scapRID="221622r508660_rule"; $Ver2=1; $scapSID="000260"; $SP80053r4="AU-12(3)"; $scapCCI="CCI-001914"; $scapSEV="III"; $scapRuleTITLE="The System Administrator (SA) and Information System Security Officer (ISSO) must configure the retention of the log records based on the defined security plan."; CheckV221622; 
$scapSTIGS++; $scapVID="221623"; $scapRID="221623r538427_rule"; $Ver2=1; $scapSID="000270"; $SP80053r4="AU-12(b)"; $scapCCI="CCI-000171"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to have full admin rights to the system."; CheckV221623; 
$scapSTIGS++; $scapVID="221625"; $scapRID="221625r508660_rule"; $Ver2=1; $scapSID="000290"; $SP80053r4="AU-5(1)"; $scapCCI="CCI-001855"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must be configured to send an immediate alert to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated log record storage volume reaches 75 percent of the repository maximum log record storage capacity."; CheckV221625; 
$scapSTIGS++; $scapVID="221626"; $scapRID="221626r508660_rule"; $Ver2=1; $scapSID="000300"; $SP80053r4="AU-5(2)"; $scapCCI="CCI-001858"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) of all audit failure events, such as loss of communications with hosts and devices, or if log records are no longer being received."; CheckV221626; 
$scapSTIGS++; $scapVID="221627"; $scapRID="221627r508660_rule"; $Ver2=1; $scapSID="000310"; $SP80053r4="AU-5(4)"; $scapCCI="CCI-001861"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must notify the System Administrator (SA) or Information System Security Officer (ISSO) if communication with the host and devices within its scope of coverage is lost."; CheckV221627; 
$scapSTIGS++; $scapVID="221628"; $scapRID="221628r508660_rule"; $Ver2=1; $scapSID="000320"; $SP80053r4="CM-6(b)"; $scapCCI="CCI-000366"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must be configured to notify the System Administrator (SA) and Information System Security Officer (ISSO), at a minimum, when an attack is detected on multiple devices and hosts within its scope of coverage."; CheckV221628; 
$scapSTIGS++; $scapVID="221629"; $scapRID="221629r508660_rule"; $Ver2=1; $scapSID="000330"; $SP80053r4="IA-5(1)(a)"; $scapCCI="CCI-000192"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must enforce password complexity for the account of last resort by requiring that at least one upper-case character be used."; CheckV221629; 
$scapSTIGS++; $scapVID="221630"; $scapRID="221630r508660_rule"; $Ver2=1; $scapSID="000340"; $SP80053r4="IA-5(1)(a)"; $scapCCI="CCI-000193"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must enforce password complexity for the account of last resort by requiring that at least one lower-case character be used."; CheckV221630; 
$scapSTIGS++; $scapVID="221631"; $scapRID="221631r508660_rule"; $Ver2=1; $scapSID="000350"; $SP80053r4="IA-5(1)(a)"; $scapCCI="CCI-000194"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must enforce password complexity for the account of last resort by requiring that at least one numeric character be used."; CheckV221631; 
$scapSTIGS++; $scapVID="221632"; $scapRID="221632r508660_rule"; $Ver2=1; $scapSID="000360"; $SP80053r4="IA-5(1)(a)"; $scapCCI="CCI-000205"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must enforce a minimum 15-character password length for the account of last resort."; CheckV221632; 
$scapSTIGS++; $scapVID="221633"; $scapRID="221633r508660_rule"; $Ver2=1; $scapSID="000370"; $SP80053r4="IA-5(1)(a)"; $scapCCI="CCI-001619"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must enforce password complexity for the account of last resort by requiring that at least one special character be used."; CheckV221633; 
$scapSTIGS++; $scapVID="221634"; $scapRID="221634r508660_rule"; $Ver2=1; $scapSID="000380"; $SP80053r4="IA-5(1)(d)"; $scapCCI="CCI-000199"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must enforce a 60-day maximum password lifetime restriction for the account of last resort."; CheckV221634; 
$scapSTIGS++; $scapVID="221635"; $scapRID="221635r508660_rule"; $Ver2=1; $scapSID="000390"; $SP80053r4="IA-5(1)(e)"; $scapCCI="CCI-000200"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must prohibit password reuse for a minimum of five generations for the account of last resort."; CheckV221635; 
$scapSTIGS++; $scapVID="221931"; $scapRID="221931r508660_rule"; $Ver2=1; $scapSID="000035"; $SP80053r4="AC-8"; $scapCCI="CCI-000048"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must display the Standard Mandatory DoD Notice and Consent Banner and accept user acknowledgement before granting access to the application."; CheckV221931; 
$scapSTIGS++; $scapVID="221932"; $scapRID="221932r508660_rule"; $Ver2=1; $scapSID="000040"; $SP80053r4="SC-23(5)"; $scapCCI="CCI-002470"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must only allow the use of DoD-approved certificate authorities for cryptographic functions."; CheckV221932; 
$scapSTIGS++; $scapVID="221933"; $scapRID="221933r508660_rule"; $Ver2=1; $scapSID="000050"; $SP80053r4="IA-7"; $scapCCI="CCI-000803"; $scapSEV="I"; $scapRuleTITLE="Splunk Enterprise must use TLS 1.2 and SHA-2 or higher cryptographic algorithms."; CheckV221933; 
$scapSTIGS++; $scapVID="221934"; $scapRID="221934r508660_rule"; $Ver2=1; $scapSID="000090"; $SP80053r4="CM-7"; $scapCCI="CCI-000381"; $scapSEV="II"; $scapRuleTITLE="When Splunk Enterprise is distributed over multiple servers, each server must be configured to disable non-essential capabilities."; CheckV221934; 
$scapSTIGS++; $scapVID="221935"; $scapRID="221935r508660_rule"; $Ver2=1; $scapSID="000100"; $SP80053r4="AU-9"; $scapCCI="CCI-000162; CCI-000163; CCI-000164; CCI-001493; CCI-001494; CCI-001495"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise installation directories must be secured."; CheckV221935; 
$scapSTIGS++; $scapVID="221936"; $scapRID="221936r508660_rule"; $Ver2=1; $scapSID="000175"; $SP80053r4="CM-6(b)"; $scapCCI="CCI-000366"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise forwarders must be configured with Indexer Acknowledgement enabled."; CheckV221936; 
$scapSTIGS++; $scapVID="221937"; $scapRID="221937r508660_rule"; $Ver2=1; $scapSID="000180"; $SP80053r4="IA-11"; $scapCCI="CCI-002038"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise idle session timeout must be set to not exceed 15 minutes."; CheckV221937; 
$scapSTIGS++; $scapVID="221938"; $scapRID="221938r508660_rule"; $Ver2=1; $scapSID="000190"; $SP80053r4="AC-12"; $scapCCI="CCI-002361"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise idle session timeout must be set to not exceed 15 minutes."; CheckV221938; 
$scapSTIGS++; $scapVID="221939"; $scapRID="221939r508660_rule"; $Ver2=1; $scapSID="000200"; $SP80053r4="AC-2(4)"; $scapCCI="CCI-001683; CCI-001684; CCI-001685; CCI-001686"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must notify the System Administrator (SA) and Information System Security Officer (ISSO) when account events are received (creation, deletion, modification, disabling)."; CheckV221939; 
$scapSTIGS++; $scapVID="221940"; $scapRID="221940r508660_rule"; $Ver2=1; $scapSID="000235"; $SP80053r4="AC-2(4)"; $scapCCI="CCI-001683; CCI-001684; CCI-001685; CCI-001686"; $scapSEV="III"; $scapRuleTITLE="Splunk Enterprise must notify analysts of applicable events for Tier 2 CSSP and JRSS only."; CheckV221940; 
$scapSTIGS++; $scapVID="221941"; $scapRID="221941r508660_rule"; $Ver2=1; $scapSID="000240"; $SP80053r4="AC-7(a)"; $scapCCI="CCI-000044"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must enforce the limit of 3 consecutive invalid logon attempts by a user during a 15 minute time period."; CheckV221941; 
$scapSTIGS++; $scapVID="221942"; $scapRID="221942r508660_rule"; $Ver2=1; $scapSID="000280"; $SP80053r4="AU-12(c)"; $scapCCI="CCI-000172"; $scapSEV="II"; $scapRuleTITLE="Splunk Enterprise must be configured with a successful/unsuccessful logon attempts report."; CheckV221942; 

ActivitySeperator 2 >> $TmpFile8
Write-Output "" >> $TmpFile8
Write-Output "$computer SCAP/STIG check evaluation results:`n" >> $TmpFile8
Write-Output "`t$scapStigs SCAP/STIG Checks evaluated by this script." >> $TmpFile8
Write-Output "`t$stigCntPass - Passed or Not A Finding (NAF)." >> $TmpFile8
Write-Output "`t$stigCntNA - NOT APPLICABLE (NA)" >> $TmpFile8
Write-Output "`t$stigCntOP - OPEN " >> $TmpFile8
Write-Output "`t$stigCntNR - NOT REVIEWED (NR)" >> $TmpFile8
Write-Output "" >> $TmpFile8
Write-Output "`tSeverity: Checked, Passed, NA, OPEN, NR" >> $TmpFile8
Write-Output "`tCAT-I:  $CHK1,  $($CHK1 - $($CHK1OP + $CHK1NA + $CHK1NR)),  $CHK1NA,  $CHK1OP,  $CHK1NR" >> $TmpFile8
Write-Output "`tCAT-II:  $CHK2,  $($CHK2 - $($CHK2OP + $CHK2NA + $CHK2NR)),  $CHK2NA,  $CHK2OP,  $CHK2NR" >> $TmpFile8
Write-Output "`tCAT-III:  $CHK3,  $($CHK3 - $($CHK3OP + $CHK3NA + $CHK3NR)),  $CHK3NA,  $CHK3OP,  $CHK3NR" >> $TmpFile8
cat $TmpFile8 >> $ArchiveOpenTXTFile
cat $TmpFile8 >> $WorkingTXTFile
cat $TmpFile8 >> $EmailTextFile

Write-output "Hardware information: $($(Get-Date).ToString("u"))"
Write-output "Hardware information: $($(Get-Date).ToString("u"))" >> $ScriptLog
FLines 2 > $Tmpfile0
HardwareAndOSInformation  >> $Tmpfile0
FLines 2 >> $Tmpfile0

Write-Output "`r`nScript execution data:`r`n`r`n`tUser:`t$env:USERNAME`n`tHost:`t$Computer`n`tDirectory:`t$([char]34)$pwd$([char]34)." >> $Tmpfile0
FLines 2 >> $Tmpfile0

cat $TmpFile0 >> $WorkingTXTFile
cat $TmpFile0 >> $ArchiveOpenTXTFile
ScriptSignature 2 >> $ArchiveOpenTXTFile
write-output "`nScript started: $ScriptStart" >> $ArchiveOpenTXTFile
write-output "Script ended: $($(Get-Date).ToString("u"))" >> $ArchiveOpenTXTFile
DocumentMarking 1 >> $ArchiveOpenTXTFile

FLines 2 >> $EmailTextFile
ScriptFilesList >> $EmailTextFile
FLines 2 >> $EmailTextFile
ScriptSignature 9 >> $EmailTextFile
write-output "`nScript started: $ScriptStart" >> $EmailTextFile
write-output "Script ended: $($(Get-Date).ToString("u"))" >> $EmailTextFile
DocumentMarking 1 >> $EmailTextFile

switch ( $ScriptEnvironment ) {
    "PROD" { ScriptFileCollection; SendReportViaEmail 5 $EmailTextFile; EraseTemporaryFiles }
    "TEAM" { ScriptFileCollection; SendReportViaEmail 0 $EmailTextFile; EraseTemporaryFiles }
    "BETA" { ScriptFileCollection; SendReportViaEmail 1 $EmailTextFile; SendReportViaEmail 2 $EmailTextFile; EraseTemporaryFiles }
    "TEST" { ScriptFileCollection; SendReportViaEmail 2 $EmailTextFile; EraseTemporaryFiles }
}

Write-output "Script exited: $($(Get-Date).ToString("u"))"
Write-output "Script exited: $($(Get-Date).ToString("u"))" >> $ScriptLog