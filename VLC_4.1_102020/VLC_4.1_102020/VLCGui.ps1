###################################################################
# VCF Lab Constructor beta v4.1 10/17/2020
# Created by: bsier@vmware.com;hjohnson@vmware.com
# QA: ktebear@vmware.com;stephenst@vmware.com
#
# PLEASE See the included install guide PDF file for more info.
###################################################################

$WarningPreference="SilentlyContinue"
$global:isExit = $false
$numHosts=0
$global:scriptDir = Split-Path $MyInvocation.MyCommand.Path
$global:VCFEMSFile = ""
$global:ovfToolPath = ""
$global:userOptions = @{}
$global:bringUpOptions = @{}
$global:bringupAfterBuild = $false
$global:validationSuccess = $false
$global:Ways = ""
$global:psVer = ""
$logPathDir = New-Item -ItemType Directory -Path "$scriptDir\Logs" -Force
$logfile = "$logPathDir\VLC-Log-_$(get-date -format `"yyyymmdd_hhmmss`").txt"

$host.ui.RawUI.WindowTitle = 'VCF Lab Constructor beta v4.1 - Process Window'
$welcomeText =@"
Welcome to:
__     ______ _____ _          _      ____                _                   _             
\ \   / / ___|  ___| |    __ _| |__  / ___|___  _ __  ___| |_ _ __ _   _  ___| |_ ___  _ __ 
 \ \ / / |   | |_  | |   / _ ` | '_ \| |   / _ \| '_ \/ __| __| '__| | | |/ __| __/ _ \| '__|
  \ V /| |___|  _| | |__| (_| | |_) | |__| (_) | | | \__ \ |_| |  | |_| | (__| || (_) | |   
   \_/  \____|_|   |_____\__,_|_.__/ \____\___/|_| |_|___/\__|_|   \__,_|\___|\__\___/|_| 
"@

write-host $welcomeText -ForegroundColor CYAN

#region Imports / Prefilght Checks

#Obtain Powershell Major version

Write-Host "Obtaining major powershell version."
$global:psVer = $($psVersionTable.psVersion.Major)
Write-Host "Major Powershell version is: $global:psVer"

# Import PowerCLI Module
Write-host "Checking PowerCLI 12.1 or greater installation."
$modCnt = 1
$moduleInstalled = Get-Module -ListAvailable | Where-Object {$_.Name -like "VMware.VimAutomation.Core"} | Select Version | Sort-Object -Property Version -Descending
    
foreach ($mod in $moduleInstalled) {
    write-host "Found PowerCLI version $($mod.Version.ToString()) installed."
    if ($mod) { 
        
        if ([System.Version]$mod.Version.ToString() -ge [System.Version]"12.1") {
            Import-Module -Name VMware.VimAutomation.Core # Latest PowerCLI
            Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -DisplayDeprecationWarnings:$false -Confirm:$false
            break
        } else {
            if($moduleInstalled.Count -ge $modCnt) {
                write-host "Please update PowerCLI to 12.1 or greater you can obtain from https://www.powershellgallery.com/packages/VMware.PowerCLI" -ForegroundColor Yellow
                exit
            }
            $modCnt++
        }
    
    } else {
        write-host "PowerCLI installation not found, attempting to install." -ForegroundColor Yellow
        $Elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ( -not $Elevated ) {
            write-host "Installing Modules requires administrator rights, please launch powershell as administrator." -ForegroundColor Yellow
            exit
        } else {
        
            $tryInstall = Read-Host -Prompt "Would you like to try and install PowerCLI now? (y/n)"
            while ($tryInstall -ne 'y') {

                if ($tryInstall -eq 'n') {  
                    write-host "Please manually install the PowerCLI module from https://code.vmware.com/ and re-run the script." -ForegroundColor Yellow
                    exit
                }
            }
            Install-Module -Name VMware.PowerCLI -ErrorAction Stop
            Import-Module -Name VMware.VimAutomation.Core # Latest PowerCLI
            Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -InvalidCertificateAction Ignore -DisplayDeprecationWarnings:$false -Confirm:$false -Scope Session
        }
    }
}

#Check if OVFTool 4.3 is installed
    write-host "Checking if VMware OVF Tool 4.3 or newer is installed."

    if ([IntPtr]::Size -eq 4) {
        $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    } else {
        $regpath = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    
    $result = Get-ItemProperty $regpath | Select DisplayName, DisplayVersion | Where {$_.DisplayName -like "VMware OVF Tool"}
    write-host "Found VMware OVF Tool version $($result.DisplayVersion.ToString()) installed."
    $ovfToolPath = $(Get-ItemProperty -Path 'HKLM:\SOFTWARE\VMware, Inc.\VMware OVF Tool\' | Select-Object InstallPath).InstallPath
    if ($result -eq $null) {
        write-host "Please Install VMware OVF Tool 4.3 or greater from https://www.vmware.com/support/developer/ovf/ and re-run the script." -ForegroundColor Yellow
        Read-Host -Prompt "Press enter to exit"
        Exit
    } elseif ([System.Version]$result.DisplayVersion -lt [System.Version]"4.3.0" ){
        write-host "Please upgrade to VMware OVF Tool 4.3 or greater from https://www.vmware.com/support/developer/ovf/ and re-run the script." -ForegroundColor Yellow
        Read-Host -Prompt "Press enter to exit"
        Exit
    }

#Import Forms
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName System.Drawing

#endregion Imports

#region Functions
#Functions
Function logger($strMessage, [switch]$logOnly,[switch]$consoleOnly)
{
	$curDateTime = get-date -format "hh:mm:ss"
	$entry = "$curDateTime :> $strMessage"
    if ($consoleOnly) {
		write-host $entry
    } elseif ($logOnly) {
		$entry | out-file -Filepath $logfile -append
	} else {
        write-host $entry
		$entry | out-file -Filepath $logfile -append
	}
}
Function Invoke-Plink ([string]$remoteHost, [string]$login, [string]$passwd, [string]$plinkOpts, [string]$command) 
{
    $plink= "& '$scriptDir\plink.exe'"
    $expCmd = "Echo Y | $plink -ssh $remoteHost -l `"$login`" -pw `"$passwd`" $plinkOpts `"$command`""
    Write-Host "Already done, no need to press anything!" -ForeGroundColor Yellow
    $passRtn = Invoke-Expression $expCmd
    return $passRtn
}
Function byteWriter($dataIn, $fileOut) 
{
    [Byte[]] $byteDataIn = [System.Text.Encoding]::UTF8.GetBytes($dataIn)
    $defaultHostPath = "$scriptDir\Temp\$fileout"
    [System.IO.File]::WriteAllBytes($defaultHostPath,$byteDataIn) 
}
Function Get-IniContent ($filePath)
{
    $ini = @{}
    switch -regex -file $FilePath
    {
        “^\[(.+)\]” # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        “^(;.*)$” # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = “Comment” + $CommentCount
            $ini[$section][$name] = $value
        } 
        “(.+?)\s*=(.*)” # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}
Function Out-IniFile($InputObject, $FilePath)
{
    $outFile = New-Item -ItemType file -Path $Filepath -Force
    foreach ($i in $InputObject.keys)
    {
        if (!($($InputObject[$i].GetType().Name) -eq “Hashtable”))
        {
            #No Sections
            Add-Content -Path $outFile -Value “$i=$($InputObject[$i])”
        } else {
            #Sections
            Add-Content -Path $outFile -Value “[$i]”
            Foreach ($j in ($InputObject[$i].keys | Sort-Object))
            {
                if ($j -match “^Comment[\d]+”) {
                    Add-Content -Path $outFile -Value “$($InputObject[$i][$j])”
                } else {
                    Add-Content -Path $outFile -Value “$j=$($InputObject[$i][$j])” 
                }

            }
            Add-Content -Path $outFile -Value “”
        }
    }
}
Function addMenuItem 
{ 
    param([ref]$ParentItem, 
    [string]$ItemName='', 
    [string]$ItemText='', 
    [scriptblock]$ScriptBlock=$null 
    ) 
    [System.Windows.Forms.ToolStripMenuItem]$private:menuItem=`
    New-Object System.Windows.Forms.ToolStripMenuItem; 
    $private:menuItem.Name =$ItemName; 
    $private:menuItem.Text =$ItemText; 
    if ($ScriptBlock -ne $null) 
        { $private:menuItem.add_Click(([System.EventHandler]$handler=`
    $ScriptBlock)); } 
    if (($ParentItem.Value) -is [System.Windows.Forms.MenuStrip]) 
        { ($ParentItem.Value).Items.Add($private:menuItem); } 
    if (($ParentItem.Value) -is [System.Windows.Forms.ToolStripItem]) 
        { ($ParentItem.Value).DropDownItems.Add($private:menuItem); } 
    return $private:menuItem; 
}
Function SetFormValues ($formContent)
{
        #VCF Settings
        $vcfSettings = $formContent.vcfsettings

        $txtDomainName.Text = $vcfSettings.domainName

        $txtMgmtNet.Text = $vcfSettings.mgmtNet
        $txtMgmtGateway.Text = $vcfSettings.mgmtNetGateway
        $txtCBLoc.Text = $vcfSettings.CBISOLoc
        $txtCBIP.Text = $vcfSettings.CBIP
        $txtNestedJSON.Text = $vcfSettings.jsonloc
        $txtNTP.Text = $vcfSettings.NTPIP
        $txtDNS.Text = $vcfSettings.DNSIP
        $txtvSphereLoc.Text = $vcfSettings.vSphereLoc
        $chkUseCBIso.Checked = $vcfSettings.UseCBIso
        $txtvmPrefix.Text = $vcfSettings.vmPrefix
	    $txtMasterPass.Text = $vcfSettings.masterPass
        $txtBringupFile.Text = $vcfSettings.bringupFile
        $chkInternalSvcs.Checked = $vcfSettings.chkInternal
        $chkSb.Checked = $vcfSettings.imageAfterBuild

 #       if ($vcfSettings.allFlash -eq "True") {
 #           $chkEC.Checked = $true
 #           } else {
 #           $chkEC.Checked = $false
 #           }

        #Target Environment Settings
        $viSettings = $formContent.visettings

        $txtHostIP.Text = $visettings.esxhost
        $txtUsername.Text = $visettings.username
        $txtPassword.Text = $visettings.password
}
Function GetFormValues ($formContent)
{
        $formContent = @{}
        $vcfSettings = @{}
        $viSettings = @{}

        #VCF Settings
        $vcfSettings.add("domainName",$txtDomainName.Text)
        $vcfSettings.add("mgmtNet",$txtMgmtNet.Text)
	    $vcfSettings.add("mgmtNetGateway",$txtMgmtGateway.Text)
	    $vcfSettings.add("CBISOLoc",$txtCBLoc.Text)
	    $vcfSettings.add("CBIP",$txtCBIP.Text)
        $vcfSettings.add("vSphereLoc",$txtvSphereLoc.Text)
        $vcfSettings.add("useCBIso",$chkUseCBIso.Checked)
        $vcfSettings.add("vmPrefix",$txtvmPrefix.Text)
	    $vcfSettings.add("jsonloc",$txtNestedJSON.Text)
	    $vcfSettings.add("masterPass",$txtMasterPass.Text)
        $vcfSettings.add("NTPIP",$txtNTP.Text)
        $vcfSettings.add("DNSIP",$txtDNS.Text)
        $vcfSettings.add("bringupFile",$txtBringupFile.Text)
	    $vcfSettings.add("imageAfterBuild",$chkSb.Checked)
#        $vcfSettings.add("allFlash",$chkEC.Checked)
        $vcfSettings.add("chkInternal",$chkInternalSvcs.Checked)
        
        #Target Environment Settings
        $viSettings.add("esxhost",$txtHostIP.Text)
        $viSettings.add("username",$txtUsername.Text)
        $viSettings.add("password",$txtPassword.Text)

        $formContent.add("vcfSettings",$vcfSettings)
        $formContent.add("viSettings",$viSettings)

        return $formContent
}
Function ValidateFormValues
{ param ($validEntries)
        #Validates each required field has an entry
		$validEntries = $true
		if(-not $txtHostIP.Text)
			{
				$lblHost.BackColor = [System.Drawing.Color]::"Red"
				$validEntries = $false				
			} else {
				$lblHost.BackColor = [System.Drawing.Color]::"Green"
			}
		if(-not $txtUsername.Text)
			{
				$lblHostUser.BackColor = [System.Drawing.Color]::"Red"
				$validEntries = $false				
			} else {
				$lblHostUser.BackColor = [System.Drawing.Color]::"Green"
			}
		if(-not $txtPassword.Text)
			{
				$lblPass.BackColor = [System.Drawing.Color]::"Red"
				$validEntries = $false				
			} else {
				$lblPass.BackColor = [System.Drawing.Color]::"Green"
			}
		if($listCluster.Items.Count -gt 0)
			{
				if($listCluster.SelectedIndex -eq -1) 
					{
						$lblCluster.BackColor = [System.Drawing.Color]::"Red"
						$validEntries = $false
					} else {
						$lblCluster.BackColor = [System.Drawing.Color]::"Green"
					}
			}
        if($listNetName.SelectedIndex -eq -1) 
			{
				$lblNetName.BackColor = [System.Drawing.Color]::"Red"
				$validEntries = $false
			} else {
				$lblNetName.BackColor = [System.Drawing.Color]::"Green"
			}
		if($listDatastore.SelectedIndex -eq -1) 
			{
				$lblDatastore.BackColor = [System.Drawing.Color]::"Red"
				$validEntries = $false
			} else {
				$lblDatastore.BackColor = [System.Drawing.Color]::"Green"
			}
        if(-not $chkUseCBIso.Checked) {
            if(-not $txtvSphereLoc.Text -or -not (Test-Path -Path $txtvSphereLoc.Text))
			    {
				    $lblvSphereLoc.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false
			    } else {
                    $lblvSphereLoc.BackColor = [System.Drawing.Color]::"Green"
                }
        }
        if($chkHostOnly.Checked) {

            if(-not $txtNestedJSON.Text -or -not (Test-Path -Path $txtNestedJSON.Text))
			    {
				    $lblNestedJSON.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false
			    } else {
                    $lblNestedJSON.BackColor = [System.Drawing.Color]::"Green"
                }

		    if(-not $txtMasterPass.Text)
			    {
				    $lblMasterPass.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false				
			    } else {
				    $lblMasterPass.BackColor = [System.Drawing.Color]::"Green"
			    }

        } else { 

            if(-not $txtMgmtGateway.Text -or -not $txtMgmtNet.Text)
			    {
				    $lblMgmtNet.BackColor = [System.Drawing.Color]::"Red"  
				    $validEntries = $false
			    } else { 
				    $lblMgmtNet.BackColor = [System.Drawing.Color]::"Green"
			    }

		    if(-not $txtCBLoc.Text -or -not (Test-Path -Path $txtCBLoc.Text))
			    {
				    $lblCBLoc.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false
			    } else {
				    $lblCBLoc.BackColor = [System.Drawing.Color]::"Green"
			    }		    
            if(-not $txtNestedJSON.Text -or -not (Test-Path -Path $txtNestedJSON.Text))
			    {
                    if($txtNestedJSON.Enabled){
                        if($txtBringUpFile.Text) {
                            $lblNestedJSON.BackColor = [System.Drawing.Color]::"Green"
                        } else {
				        $lblNestedJSON.BackColor = [System.Drawing.Color]::"Red"
				        $validEntries = $false
                        }
                    }

			    } else {
                    $lblNestedJSON.BackColor = [System.Drawing.Color]::"Green"
                }
		    if(-not $txtMasterPass.Text)
			    {
				    $lblMasterPass.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false				
			    } else {
				    $lblMasterPass.BackColor = [System.Drawing.Color]::"Green"
			    }
            if($chkSb.Checked -and -not $txtBringupFile.Text)
                {
                    $lblBringupFile.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false
                } else {
                    $lblBringupFile.BackColor = [System.Drawing.Color]::"Green"
                }
            if($chkInternalSvcs.Checked -and -not $txtBringupFile.Text)
                {
                    $lblBringupFile.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false
                } else {
                    $lblBringupFile.BackColor = [System.Drawing.Color]::"Green"
                }
            if(-not $txtDNS.Text)
                {
                    $lblDNS.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false
                }
            if(-not $txtNTP.Text)
                {
                    $lblNTP.BackColor = [System.Drawing.Color]::"Red"
				    $validEntries = $false
                }
        }

        if ($validEntries)
            {
                $viConnection = connectVI -vmHost $txtHostIP.Text -vmUser $txtUsername.Text -vmPassword $txtPassword.Text
                <#logger "Validating Jump VM network connectivity to Portgroup"
                $vmNetToTest = $listNetName.SelectedItem
                $vmSwitchToTest = $(Get-VirtualPortGroup -Name $vmNetToTest | Select VirtualSwitch).VirtualSwitch
                if ($listCluster.Items.Count -gt 0) 
                    {
                        $vmClusterForTest = $listCluster.SelectedItem
                        $vmHostForTest = Get-VMHost -Location $vmClusterForTest | Select -First 1
                    } else {
                        $vmHostForTest = Get-VMHost
                    }
                #>                   
                logger "Validating Free Space on Datastore 800GB or more for deployment, 300GB or more for Expansion."
                $vmDSToTest = $listDatastore.SelectedItem
                $vmDSFree = $(Get-DataStore $vmDSToTest | Select FreeSpaceGB).FreeSpaceGB
                if ($global:Ways -match "expansion")
                    {
                        if ($vmDSFree -le 300)
                            {
                                logger "Current free space on datastore $vmDSToTest is $([Math]::Round($vmDSFree)). 300GB Free is the minimum required for expansion."
                                $lblDatastore.BackColor = [System.Drawing.Color]::"Red"
				                $validEntries = $false
                                $wshell = New-Object -ComObject Wscript.Shell
                                $wshell.Popup("Current free space on datastore $vmDSToTest is $([Math]::Round($vmDSFree))GB. 300GB Free is the minimum required for expansion.",0,"Check Datastore Free space",1+4096)
                            } else {
                                logger "Current free space on datastore $vmDSToTest is $([Math]::Round($vmDSFree))GB. Validation Passed."
                            }
                    } else {
                        if ($vmDSFree -le 800)
                            {
                                logger "Current free space on datastore $vmDSToTest is $([Math]::Round($vmDSFree)). 800GB Free is the minimum required for deployment."
                                $lblDatastore.BackColor = [System.Drawing.Color]::"Red"
				                $validEntries = $false
                                $wshell = New-Object -ComObject Wscript.Shell
                                $wshell.Popup("Current free space on datastore $vmDSToTest is $([Math]::Round($vmDSFree))GB. 800GB Free is the minimum required for deployment.",0,"Check Datastore Free space",1+4096)
                            } else {
                                logger "Current free space on datastore $vmDSToTest is $([Math]::Round($vmDSFree))GB. Validation Passed."
                            }
                     }
            }
		$global:validationSuccess = $validEntries
}
Function connectVI ($vmHost, $vmUser, $vmPassword, $numTries)
{
    $i=1
        try {
        Write-host "Connecting to VI, please wait.." -ForegroundColor green
        logger "Connecting to VI, please wait.." -logOnly
        #Connect to vCenter
        Set-PowerCLIConfiguration -Scope Session -WebOperationTimeoutSeconds 30 -Confirm:$false
        Connect-viserver -Server $vmHost -user $vmUser -password $vmPassword -ErrorAction Stop
        } catch [Exception]{
            $status = 1
            $exception = $($_.Exception.Message).Split("`t")
            logger $exception
            $wshell = New-Object -ComObject Wscript.Shell
            $wshell.Popup($exception,0,"Check VI Connection",1+4096)
            Write-Host "Could not connect to VI, try #$i" -ForegroundColor Red
            if ($i -ge $numTries) {
                logger "Unable to connect to VI after $i tries."
                $msg = "Could not connect to VI."
            }
            #sleep 30
            $i++
            #Continue
        }
    Set-PowerCLIConfiguration -Scope Session -WebOperationTimeoutSeconds 300 -Confirm:$false
}

Function ClearFormFields 
{
        $txtBringupFile.Text = ""
        $txtDomainName.Text = ""
        $txtMgmtNet.Text = ""
	    $txtMgmtGateway.Text = ""
	    $txtCBLoc.Text = ""
	    $txtNestedJSON.Text = ""
	    $txtMasterPass.Text = ""
        $txtvSphereLoc.Text = ""
        $txtvmPrefix.Text = ""
        $txtCBIP.Text = ""
        $txtDNS.Text = ""
        $txtNTP.Text = ""
	    $chkInternalSvcs.Checked = $false
        $chkSb.Checked = $false
#        $chkEC.Checked = $false
        #Target Environment Settings
        $viSettings = ""
        $txtHostIP.Text = ""
        $txtUsername.Text = ""
        $txtPassword.Text = ""
}
Function LockFormFields 
{
        $txtBringupFile.Enabled=$false
        $txtDomainName.Enabled=$false
        $txtMgmtNet.Enabled=$false
	    $txtMgmtGateway.Enabled=$false
	    $txtCBLoc.Enabled=$false
	    $txtNestedJSON.Enabled=$false
	    $txtMasterPass.Enabled=$false
        $txtvSphereLoc.Enabled=$false
        $txtvmPrefix.Enabled=$false
        $txtCBIP.Enabled=$false
        $txtDNS.Enabled=$false
        $txtNTP.Enabled=$false
	    $chkInternalSvcs.Enabled=$false
        $chkSb.Enabled=$false
#        $chkEC.Enabled=$false
        $chkUseCBIso.Enabled=$false
        $txtHostIP.Enabled=$false
        $txtUsername.Enabled=$false
        $txtPassword.Enabled=$false
        $listCluster.Enabled=$false
        $listNetName.Enabled=$false
        $listDataStore.Enabled=$false
}
Function UnLockFormFields 
{
        $txtBringupFile.Enabled=$true
        $txtDomainName.Enabled=$true
        $txtMgmtNet.Enabled=$true
	    $txtMgmtGateway.Enabled=$true
	    $txtCBLoc.Enabled=$true
	    $txtNestedJSON.Enabled=$true
	    $txtMasterPass.Enabled=$true
        $txtvSphereLoc.Enabled=$true
        $txtvmPrefix.Enabled=$true
        $txtCBIP.Enabled=$true
        $txtDNS.Enabled=$true
        $txtNTP.Enabled=$true
	    $chkInternalSvcs.Enabled=$true
        $chkSb.Enabled=$true
#        $chkEC.Enabled=$true
        $chkUseCBIso.Enabled=$true
        $txtHostIP.Enabled=$true
        $txtUsername.Enabled=$true
        $txtPassword.Enabled=$true
        $listCluster.Enabled=$true
        $listNetName.Enabled=$true
        $listDataStore.Enabled=$true
}
Function Get-FileName($initialDirectory, $filterParam, $action)
{
    if ($action -eq "load") {
            [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    
            $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $OpenFileDialog.initialDirectory = $initialDirectory
            $OpenFileDialog.filter = $filterParam
            $OpenFileDialog.ShowDialog() | Out-Null
            $OpenFileDialog.filename
    }
    if ($action -eq "save") {
            [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    
            $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
            $OpenFileDialog.initialDirectory = $initialDirectory
            $OpenFileDialog.filter = $filterParam
            $OpenFileDialog.ShowDialog() | Out-Null
            $OpenFileDialog.filename
    }
}
Function Get-VIInfo($vmHost, $vmUser, $vmPassword)
{
#    $isVIConnected = Connect-VIServer -Server $vmHost -User $vmUser -Password $vmPassword
    $isVIConnected = connectVI -vmHost $vmHost -vmUser $vmUser -vmPassword $vmPassword
    $vmCluster = ""
    $vmNetworks = ""
    $vmSwitches=  ""
    $vmdatastore = ""
    $listCluster.Items.Clear()
    $listNetName.Items.Clear()
    $listDatastore.Items.Clear()
    $listResourcePool.Items.Clear()
    $viValidated = $false
    $fakeScsiSet=$true
        if ($isVIConnected.IsConnected) {
            $btnConnect.Backcolor = [System.Drawing.Color]::"DarkGreen"
            $btnConnect.ForeColor = [System.Drawing.Color]::"White"  
            $btnConnect.Text = "Connected!"     
#Begin Validation of, Cluster HA and DRS settings, VSAN Cluster FakeSCSIReservations, Standalone host managed by VC.
                [System.Collections.ArrayList]$vmNetworks = Get-VirtualPortGroup -Server $vmHost.Text -ErrorAction:SilentlyContinue
                $vmdatastore = Get-Datastore -Server $vmHost.Text
                $productLine = $isVIConnected.ProductLine
                If ($productLine -eq "vpx") {
                    $clusterOKFlag = @{}
                    $vmCluster = Get-Cluster -Server $vmHost.Text
                    $listCluster.Enabled = $true
                    $listResourcePool.Enabled = $true       
                    ForEach ($item in $vmCluster) {
                        $errArray = @()
                        logger "Checking for 1 or more hosts in cluster $($item.Name)"                  
                        
                        If ($($item.ExtensionData.Host.Count) -le 0) {
                            $errArray += "nohost"
                        } 
                        
                        logger "Checking HA / DRS settings for cluster $($item.Name)"                  
                        
                        If ($item.HAEnabled -Or $($item.DrsEnabled -And $item.DrsAutomationLevel -eq "FullyAutomated")) {
                            $errArray += "hadrs"
                        }
                        
                        logger "Checking FakeISCIReservations for cluster $($item.Name)"                  
                        
                        If ($item.VsanEnabled) {
                            $clusterHosts = Get-VMHost -Location $item
                            foreach ($cHost in $clusterHosts) {
                                $fakeScsi = $(Get-AdvancedSetting -Entity $cHost -Name "VSAN.FakeSCSIReservations").Value
                                if ($fakeScsi -ne 1){
                                     $errArray += "fakescsi"
                                }
                            }
                        }
                        if ($errArray.Length -gt 0) {
                            $clusterOKFlag.Add($($item.Name),$errArray)
                        }              
                        else {
                            logger "Cluster $($item.Name) is valid for VLC!"
                            #$resourcePools = $(Get-ResourcePool -Location $item | Where-Object {$_.Parent -inotlike $($item.Name)}).Name
                            $listCluster.Items.Add($item.Name)
                            #$listResourcePool.Items.Add($resourcePools)
                            $viValidated = $true
                        }

                    }
            
                    foreach ($validErr in $clusterOKFlag.Keys) {
                        foreach ($innerErr in $clusterOKFlag["$validErr"]){
                            $popMsg += switch ($innerErr) {
                                "nohost" {"Cluster $validErr does not have any hosts.`n";break}
                                "hadrs" {"Cluster $validErr will need HA disabled and DRS either disabled or set to Partially Automated or Manual to use.`n";break}
                                "fakescsi" {"Cluster $validErr will need the FakeSCSIReservations advanced setting to 1 on the hosts in the cluster.`n";break}
                            }
                        }
                    }
                        logger "VLC VI Validation warnings:`n-----------------------------------------------`n$popMsg"
                    if ($listCluster.Items.Count -eq 0) {
                        $wshell = New-Object -ComObject Wscript.Shell
                        $popMsg +="Once fixed click connect again to refresh.`n"
                        $wshell.Popup($popMsg,0,"Check Cluster Settings",1+4096)
                        $btnConnect.Backcolor = [System.Drawing.Color]::"Yellow"
                        $btnConnect.ForeColor = [System.Drawing.Color]::"Black"
                        $btnConnect.Text = "Connect"

                    }
                } else {
                    $isVCControlled = $false
                    $hostToTest = Get-VMhost
                    logger "Creating a test VM and setting the SCSI controller as it's the only reliable way to determine VC Control of a host"
                    $testVCVM = New-VM -Name "TestVCVM" -VMHost $hostToTest -Confirm:$false
                    $testSCSI = Get-ScsiController -VM $($testVCVM.Name)
                    Try {
                        
                        Set-ScsiController $testSCSI -Type ParaVirtual -ErrorAction Stop

                    } Catch {
                    
                        logger "$_.Exception.Message"
                        $isVCControlled = $true
                    
                    }
                    Remove-VM -VM $($testVCVM.Name) -DeletePermanently:$true -Confirm:$false | Out-Null
                    if ($isVCControlled) {
                            $wshell = New-Object -ComObject Wscript.Shell
                            $wshell.Popup("This host is managed by a vCenter, please target the vCenter or disconnect the host from vCenter management. Once fixed click connect again to refresh.",0,"Check Host Settings",1+4096)
                            logger "This host is managed by a vCenter, please target the vCenter or disconnect the host from vCenter management. Once fixed click connect again to refresh."
                            $btnConnect.Backcolor = [System.Drawing.Color]::"Yellow"
                            $btnConnect.ForeColor = [System.Drawing.Color]::"Black"
                            $btnConnect.Text = "Connect"
                            Disconnect-VIServer * -Force:$true -Confirm:$false | Out-Null
                    } else {
                            $viValidated = $true
                    }        
                }    
#End Validation of Cluster HA and DRS settings, VSAN Cluster FakeSCSIReservations, Standalone host managed by VC.
#Begin Validation of Virtual Switch MTU, Security Policy                       
            if ($viValidated) {
                $vSwitches = ""
                $vSwitches = $(Get-VirtualPortGroup | Select VirtualSwitch -Unique).VirtualSwitch
                ForEach ($switch in $vSwitches){           
                    if ($switch.Mtu -lt 8940) {  
                        logger "$($switch.Name) MTU of $($switch.Mtu) is not valid for VLC, must be 8940 or higher."
                        logger "Networks from this switch will not be available as deploy target until corrected"
                        $invalidNets = $vmNetworks | Where VirtualSwitch -ilike $switch
                        ForEach ($netWk in $invalidNets){$vmNetworks.Remove($netWk)}
                        $vSwitchMTUFail = $true
                    }
                }
                ForEach ($item in $vmNetworks) {
   
                        if ($item.key -like "dvportgroup-*") {
                            $isSecSet = $item.ExtensionData.Config.DefaultPortConfig.SecurityPolicy
                            If ($isSecSet.AllowPromiscuous.Value -and $isSecSet.ForgedTransmits.Value -and $isSecSet.MacChanges.Value){                 
                                $listNetName.Items.Add($item.Name) 
                            } else {
                                logger "$($item.Name) on $($vSwitch.Name) security settings are not valid for VLC! Please enable the security options on the portgroup. Allow Promiscous/Forged transmits/MAC Changes"
                            }
                        } else {                
                            $isSecSet = $item.ExtensionData.Spec.Policy.Security
                            If ($isSecSet.AllowPromiscuous -and $isSecSet.ForgedTransmits -and $isSecSet.MacChanges) {                                                     
                                $listNetName.Items.Add($item.Name)  
                            } else {
                                logger "$($item.Name) on $($item.VirtualSwitch) security settings are not valid for VLC!"
                            }       
                        }
                }

            }
                If ($listNetName.Items.Count -eq 0) {
                    if ($vSwitchMTUFail) {
                        $wshell = New-Object -ComObject Wscript.Shell
                        $wshell.Popup("Please check MTU of your virtual switches.",0,"Check Virtual Switch MTU Settings",1+4096)
                    } else {
                        $wshell = New-Object -ComObject Wscript.Shell
                        $wshell.Popup("Please check portgroup security policies and click the Connect button again.",0,"Check PortGroup Security Settings",1+4096)
                    }
                }
                ForEach ($item in $vmdatastore) {
                    $listDatastore.Items.Add($item.Name)
                }
        } else {
            $btnConnect.BackColor = [System.Drawing.Color]::"Red"
            $btnConnect.ForeColor = [System.Drawing.Color]::"White"
            $btnConnect.Text = "Connect"       
        }
    Disconnect-VIServer * -Confirm:$false -Force
}       
function extractvSphereISO ($vSphereISOPath) 
{

    $mount = Mount-DiskImage -ImagePath "$vSphereISOPath" -PassThru

         if($mount) {
         
             $volume = Get-DiskImage -ImagePath $mount.ImagePath | Get-Volume
             $source = $volume.DriveLetter + ":\*"
             $folder = mkdir $scriptDir\temp\ISO -Force
         
             logger "Extracting '$vsphereISOPath' to '$folder'..."
		 
             $params = @{Path = $source; Destination = $folder; Recurse = $true; Force = $true;}
             cp @params
             $hide = Dismount-DiskImage -ImagePath "$vSphereISOPath"
             logger "Copy complete"
        }
        else {
             logger "ERROR: Could not mount $vSphereISOPath check if file is already in use"
             exit
        }
}
Function Test-IP ($ipAdx,$iptype)
{  

   if ($iptype -eq "subnet") {

    if($ipAdx -match "^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$"){

        return $true
    
    }
   }
    
   if($ipAdx -match "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"){

        return $true
    
    } else {
    
        return $false
   }
    
}
Function IS-InSubnet() 
{ 
 
[CmdletBinding()] 
[OutputType([bool])] 
Param( 
                    [Parameter(Mandatory=$true, 
                     ValueFromPipelineByPropertyName=$true, 
                     Position=0)] 
                    [validatescript({([System.Net.IPAddress]$_).AddressFamily -match 'InterNetwork'})] 
                    [string]$ipaddress="", 
                    [Parameter(Mandatory=$true, 
                     ValueFromPipelineByPropertyName=$true, 
                     Position=1)] 
                    [validatescript({(([system.net.ipaddress]($_ -split '/'|select -first 1)).AddressFamily -match 'InterNetwork') -and (0..32 -contains ([int]($_ -split '/'|select -last 1) )) })] 
                    [string]$Cidr="" 
    ) 
Begin{ 
        [int]$BaseAddress=[System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse(($cidr -split '/'|select -first 1))).GetAddressBytes()),0) 
        [int]$Address=[System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($ipaddress).GetAddressBytes()),0) 
        [int]$mask=[System.Net.IPAddress]::HostToNetworkOrder(-1 -shl (32 - [int]($cidr -split '/' |select -last 1))) 
} 
Process{ 
        if( ($BaseAddress -band $mask) -eq ($Address -band $mask)) 
        { 
 
            $status=$True 
        }else { 
 
        $status=$False 
        } 
} 
end { return $status } 
} 
Function cbConfigurator
{

    Param (

        [parameter(Mandatory=$true)]
        [Net.IPAddress]$CloudBuilderIP,
        [parameter(Mandatory=$true)]
        [ValidateRange(8,28)]
        [Int]$CloudBuilderCIDR,
        [parameter(Mandatory=$true)]
        [Net.IPAddress]$CloudBuilderGateway,
        [Net.IPAddress]$DhcpIPSubnet = "172.16.254.0",
        [INT]$DhcpSubnetCIDR = "24",
        [Net.IPAddress]$DhcpGateway = "172.16.254.1",
        [parameter(Mandatory=$true)]
        [String]$vcfDomainName,
        [String]$CBName
    )

    $dnsIPFQDNs = compileDNSRecords
    [Net.IPAddress]$DhcpSubnetMask = (('1'*$DhcpSubnetCIDR+'0'*(32-$DhcpSubnetCIDR)-split'(.{8})')-ne''|%{[convert]::ToUInt32($_,2)})-join'.'
    [Net.IPAddress]$CloudBuilderSubnetMask = (('1'*$CloudBuilderCIDR+'0'*(32-$CloudBuilderCIDR)-split'(.{8})')-ne''|%{[convert]::ToUInt32($_,2)})-join'.'
    [Net.IPAddress]$CloudBuilderIPSubnet =  ($([Net.IPAddress]$CloudBuilderIP).address -band ([Net.IPAddress]$CloudBuilderSubnetMask).address)
    $DhcpServerIP = $DhcpIPSubnet.ToString().Substring(0,($DhcpIPSubnet.ToString().LastIndexOf(".")+1)) + 199
    $DhcpRangeStart = $DhcpIPSubnet.ToString().Substring(0,($DhcpServerIP.ToString().LastIndexOf(".")+1)) + 10
    $DhcpRangeEnd = $DhcpIPSubnet.ToString().Substring(0,($DhcpServerIP.ToString().LastIndexOf(".")+1)) + 100
    $revArray = $CloudBuilderIP.ToString().Split(".") | select -first 3
    $reverseDNS = "$($revArray[($revArray.Count-1)..0] -join '.').in-addr.arpa."
    $regionSubnet = $($Global:bringUpOptions | Select -ExpandProperty networkSpecs | Where-object -Property networkType -Match 'REGION_SPECIFIC').subnet
    $xregionSubnet = $($Global:bringUpOptions | Select -ExpandProperty networkSpecs | Where-object -Property networkType -Match 'X_REGION').subnet
    $revRegionArray = $($Global:bringUpOptions | Select -ExpandProperty networkSpecs | Where-object -Property networkType -Match 'REGION_SPECIFIC').subnet.ToString().Split(".") | Select -First 3
    $revRegionDNS = "$($revRegionArray[($revRegionArray.Count-1)..0] -join '.').in-addr.arpa."
    $revxRegionArray = $($Global:bringUpOptions | Select -ExpandProperty networkSpecs | Where-object -Property networkType -Match 'X_REGION').subnet.ToString().Split(".") | Select -First 3
    $revxRegionDNS = "$($revxRegionArray[($revxRegionArray.Count-1)..0] -join '.').in-addr.arpa."

    $avnNetworkInfo = $($global:bringUpOptions | Select -ExpandProperty networkSpecs)
    $avnNets = $avnNetworkInfo |  where {$_.networkType -match "REGION"} | Select -expand subnet
    $bgpNeighborInfo = $($global:bringUpOptions | Select -ExpandProperty nsxtSpec | Select -ExpandProperty nsxtEdgeSpec | Select -ExpandProperty bgpNeighbours)  
    $uplinkInfo = $($avnNetworkInfo | Where -Property networkType -match "UPLINK")
    $uplinkAddrs = $uplinkInfo | Select -ExpandProperty gateway | foreach {"$_/$($($uplinkInfo | Select -ExpandProperty subnet).Split('/')[1])"}
    $edgeCidrs = $bringUpOptions | Select -Expand nsxtSpec | Select -Expand nsxtEdgeSpec | Select -Expand edgeNodeSpecs | Select -Expand Interfaces | Select -ExpandProperty interfaceCidr
    $edgeTEPInfo = $($avnNetworkInfo | Where -Property networkType -match "NSXT_EDGE_TEP")

    $replaceNet =""

    $replaceNet +="echo $($userOptions.masterPassword) | sudo su - <<END`n"
    $replaceNet +="cp /etc/systemd/network/10-eth0.network /etc/systemd/network/10-eth0.network.orig`n"
    $replaceNet +="cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.orig`n"
    $replaceNet +="cp /etc/ntp.conf /etc/ntp.conf.orig`n"
    $replaceNet +="modprobe 8021q`n"
    if($($userOptions.mgmtNetVlan) -ne 0) {
        $mgmtVlanId = $userOptions.mgmtNetVlan
        #eth0.x config on CloudBuilder
        $replaceNet +="(`n"
        $replaceNet +="echo [Match]`n"
        $replaceNet +="echo Name=eth0`n"
        $replaceNet +="echo [Network]`n"
        $replaceNet +="echo DHCP=no`n"
        $replaceNet +="echo DNS=$CloudBuilderIP`n"
        $replaceNet +="echo Domains=$vcfDomainname`n"
        $replaceNet +="echo NTP=$CloudBuilderIP`n"
        $replaceNet +="echo VLAN=eth0.$($mgmtVlanId)`n"
        $replaceNet +="echo VLAN=eth0.$($upLinkInfo.VLANid[0])`n"
        $replaceNet +="echo VLAN=eth0.$($upLinkInfo.VLANid[1])`n"
        $replaceNet +="echo VLAN=eth0.$($edgeTEPInfo.VLANid)`n"
        $replaceNet +=")>/etc/systemd/network/10-eth0.network`n"
        $replaceNet +="(`n"
        $replaceNet +="echo [NetDev]`n"
        $replaceNet +="echo Name=eth0.$($mgmtVlanId)`n"
        $replaceNet +="echo Kind=vlan`n"
        $replaceNet +="echo [VLAN]`n"
        $replaceNet +="echo Id=$($mgmtVlanId)`n"
        $replaceNet +=")>/etc/systemd/network/eth0.$($mgmtVlanId).netdev`n"
        $replaceNet +="(`n"
        $replaceNet +="echo [Match]`n"
        $replaceNet +="echo Name=eth0.$($mgmtVlanId)`n"
        $replaceNet +="echo [Network]`n"
        $replaceNet +="echo DHCP=no`n"
        $replaceNet +="echo Address=$DhcpServerIP/$DhcpSubnetCIDR`n"
        $replaceNet +="echo Address=$CloudBuilderIP/$CloudBuilderCIDR`n"
        $replaceNet +="echo Address=$DhcpGateway/$DhcpSubnetCIDR`n"
        $replaceNet +="echo Gateway=$CloudBuilderGateway`n"
        $replaceNet +=")>/etc/systemd/network/eth0.$($mgmtVlanId).network`n"
    } else {
    #eth0 config on CloudBuilder
        $replaceNet +="(`n"
        $replaceNet +="echo [Match]`n"
        $replaceNet +="echo Name=eth0`n"
        $replaceNet +="echo [Network]`n"
        $replaceNet +="echo DHCP=no`n"
        $replaceNet +="echo Address=$DhcpServerIP/$DhcpSubnetCIDR`n"
        $replaceNet +="echo Address=$CloudBuilderIP/$CloudBuilderCIDR`n"
        $replaceNet +="echo Address=$DhcpGateway/$DhcpSubnetCIDR`n"
        $replaceNet +="echo Gateway=$CloudBuilderGateway`n"
        $replaceNet +="echo DNS=$CloudBuilderIP`n"
        $replaceNet +="echo Domains=$vcfDomainname`n"
        $replaceNet +="echo NTP=$CloudBuilderIP`n"
        $replaceNet +="echo VLAN=eth0.$($upLinkInfo.VLANid[0])`n"
        $replaceNet +="echo VLAN=eth0.$($upLinkInfo.VLANid[1])`n"
        $replaceNet +="echo VLAN=eth0.$($edgeTEPInfo.VLANid)`n"
        $replaceNet +=")>/etc/systemd/network/10-eth0.network`n"
    }
#Uplink01
    $replaceNet +="(`n"
    $replaceNet +="echo [NetDev]`n"
    $replaceNet +="echo Name=eth0.$($upLinkInfo.VLANid[0])`n"
    $replaceNet +="echo Kind=vlan`n"
    $replaceNet +="echo [VLAN]`n"
    $replaceNet +="echo Id=$($upLinkInfo.VLANid[0])`n"
    $replaceNet +=")>/etc/systemd/network/eth0.$($upLinkInfo.VLANid[0]).netdev`n"
    $replaceNet +="(`n"
    $replaceNet +="echo [Match]`n"
    $replaceNet +="echo Name=eth0.$($upLinkInfo.VLANid[0])`n"
    $replaceNet +="echo [Network]`n"
    $replaceNet +="echo DHCP=no`n"
    $replaceNet +="echo Address=$($uplinkAddrs[0])`n"
    $replaceNet +="echo Address=$($bgpNeighborInfo[0].neighbourIp)/$CloudBuilderCIDR`n"
    $replaceNet +=")>/etc/systemd/network/eth0.$($upLinkInfo.VLANid[0]).network`n"
#Uplink02
    $replaceNet +="(`n"
    $replaceNet +="echo [NetDev]`n"
    $replaceNet +="echo Name=eth0.$($upLinkInfo.VLANid[1])`n"
    $replaceNet +="echo Kind=vlan`n"
    $replaceNet +="echo [VLAN]`n"
    $replaceNet +="echo Id=$($upLinkInfo.VLANid[1])`n"
    $replaceNet +=")>/etc/systemd/network/eth0.$($upLinkInfo.VLANid[1]).netdev`n"
    $replaceNet +="(`n"
    $replaceNet +="echo [Match]`n"
    $replaceNet +="echo Name=eth0.$($upLinkInfo.VLANid[1])`n"
    $replaceNet +="echo [Network]`n"
    $replaceNet +="echo DHCP=no`n"
    $replaceNet +="echo Address=$($uplinkAddrs[1])`n"
    $replaceNet +="echo Address=$($bgpNeighborInfo[1].neighbourIp)/$CloudBuilderCIDR`n"
    $replaceNet +=")>/etc/systemd/network/eth0.$($upLinkInfo.VLANid[1]).network`n"
#Edge Overlay
    $replaceNet +="(`n"
    $replaceNet +="echo [NetDev]`n"
    $replaceNet +="echo Name=eth0.$($edgeTEPInfo.VLANid)`n"
    $replaceNet +="echo Kind=vlan`n"
    $replaceNet +="echo [VLAN]`n"
    $replaceNet +="echo Id=$($edgeTEPInfo.VLANid)`n"
    $replaceNet +=")>/etc/systemd/network/eth0.$($edgeTEPInfo.VLANid).netdev`n"
    $replaceNet +="(`n"
    $replaceNet +="echo [Match]`n"
    $replaceNet +="echo Name=eth0.$($edgeTEPInfo.VLANid)`n"
    $replaceNet +="echo [Network]`n"
    $replaceNet +="echo DHCP=no`n"
    $replaceNet +="echo Address=$($edgeTEPInfo.gateway)/$($edgeTEPInfo.subnet.Split("/")[1])`n"
    $replaceNet +=")>/etc/systemd/network/eth0.$($edgeTEPInfo.VLANid).network`n"
    $replaceNet +="chmod 644 /etc/systemd/network/*.net*`n"
    $replaceNet +="systemctl enable systemd-networkd-wait-online.service`n"
    $replaceNet +="systemctl restart systemd-networkd`n"
#DHCP Config
    $replaceNet +="(`n"
    $replaceNet +="echo option domain-name \`"$vcfDomainname\`"\;`n"
    $replaceNet +="echo option domain-name-servers $CloudBuilderIP\;`n"
    $replaceNet +="echo `n"
    $replaceNet +="echo default-lease-time 600\;`n"
    $replaceNet +="echo max-lease-time 7200\;`n"
    $replaceNet +="echo `n"
    $replaceNet +="echo subnet $CloudBuilderIPSubnet netmask $CloudBuilderSubnetMask {`n"
    $replaceNet +="echo }`n"
    $replaceNet +="echo `n"
    $replaceNet +="echo subnet $DhcpIPSubnet netmask $DhcpSubnetMask {`n"
    $replaceNet +="echo   range $DhcpRangeStart $DhcpRangeEnd\;`n"
    $replaceNet +="echo   option routers $DhcpGateway\;`n"
    $replaceNet +="echo }`n"
    $replaceNet +=")>/etc/dhcp/dhcpd.conf`n"
    $replaceNet +="(`n"
    $replaceNet +="echo [Unit]`n"
    $replaceNet +="echo Description=IPv4 DHCP server on %I`n"
    $replaceNet +="echo Wants=systemd-networkd-wait-online.service`n"
    $replaceNet +="echo After=systemd-networkd-wait-online.service`n"
    $replaceNet +="echo `n"
    $replaceNet +="echo [Service]`n"
    $replaceNet +="echo Type=forking`n"
    $replaceNet +="echo PIDFile=/run/dhcpd4.pid`n"
    $replaceNet +="echo ExecStart=/usr/sbin/dhcpd -4 -q -pf /run/dhcpd4.pid %I`n"
    $replaceNet +="echo KillSignal=SIGINT`n"
    $replaceNet +="echo `n"
    $replaceNet +="echo [Install]`n"
    $replaceNet +="echo WantedBy=multi-user.target`n"
    $replaceNet +=")>/etc/systemd/system/dhcpd4@.service`n"
    if($mgmtVlanId -in 1..4094) {
        $replaceNet +="systemctl enable dhcpd4\@eth0.$mgmtVlanId.service`n"
    } else {
        $replaceNet +="systemctl enable dhcpd4\@eth0.service`n"
    }
    $replaceNet +="(`n"
    $replaceNet +="echo [Unit]`n"
    $replaceNet +="echo Description=Network interface initialization`n"
    $replaceNet +="echo After=local-fs.target network-online.target network.target`n"
    $replaceNet +="echo Wants=local-fs.target network-online.target network.target`n"
    $replaceNet +="echo `n"
    $replaceNet +="echo [Service]`n"
    $replaceNet +="echo ExecStart=/sbin/ifconfig eth0 mtu 8940 up`n"
    $replaceNet +="echo ExecStart=/sbin/ifconfig eth0.$($mgmtVlanId) mtu 8940 up`n"
    $replaceNet +="echo ExecStart=/sbin/ifconfig eth0.$($upLinkInfo.VLANid[1]) mtu 8940 up`n"
    $replaceNet +="echo ExecStart=/sbin/ifconfig eth0.$($upLinkInfo.VLANid[0]) mtu 8940 up`n"
    $replaceNet +="echo ExecStart=/sbin/ifconfig eth0.$($edgeTEPInfo.VLANid) mtu 8940 up`n"
    $replaceNet +="echo ExecStart=ip route add $($avnNets[0]) proto static scope global nexthop dev eth0.$($upLinkInfo.VLANid[0]) via $($edgeCidrs[0].Split("/")[0]) weight 1 nexthop dev eth0.$($upLinkInfo.VLANid[0]) via $($edgeCidrs[2].Split("/")[0]) weight 1 nexthop dev eth0.$($upLinkInfo.VLANid[1]) via $($edgeCidrs[1].Split("/")[0]) weight 1 nexthop dev eth0.$($upLinkInfo.VLANid[1]) via $($edgeCidrs[3].Split("/")[0]) weight 1`n"
    $replaceNet +="echo ExecStart=ip route add $($avnNets[1]) proto static scope global nexthop dev eth0.$($upLinkInfo.VLANid[0]) via $($edgeCidrs[0].Split("/")[0]) weight 1 nexthop dev eth0.$($upLinkInfo.VLANid[0]) via $($edgeCidrs[2].Split("/")[0]) weight 1 nexthop dev eth0.$($upLinkInfo.VLANid[1]) via $($edgeCidrs[1].Split("/")[0]) weight 1 nexthop dev eth0.$($upLinkInfo.VLANid[1]) via $($edgeCidrs[3].Split("/")[0]) weight 1`n"
    $replaceNet +="echo Type=oneshot`n"
    $replaceNet +="echo `n"
    $replaceNet +="echo [Install]`n"
    $replaceNet +="echo WantedBy=multi-user.target`n"
    $replaceNet +=")>/etc/systemd/system/ethMTU.service`n"
    $replaceNet +="systemctl enable ethMTU.service`n"

#NTP Config
    $replaceNet +="(`n"
    $replaceNet +="echo tinker panic 0`n"
    $replaceNet +="echo restrict default kod nomodify notrap nopeer noquery`n"
    $replaceNet +="echo restrict $CloudBuilderIPSubnet mask $CloudBuilderSubnetMask`n"
    $replaceNet +="echo restrict 127.0.0.1`n"
    $replaceNet +="echo server 127.127.1.0`n"
    $replaceNet +="echo fudge 127.127.1.0 stratum 10`n"
    $replaceNet +=")>/etc/ntp.conf`n"
#NFS and other service config
    $replaceNet +="mkdir /nfsexport`n"
    $replaceNet +="chmod 777 /nfsexport`n"
    $replaceNet +="echo '/nfsexport *(rw,sync,no_subtree_check,no_root_squash)' > /etc/exports`n"
    $replaceNet +="systemctl enable nfs-server`n"
    $replaceNet +="iptables -P OUTPUT ACCEPT`n"
    $replaceNet +="iptables -P INPUT ACCEPT`n"
    $replaceNet +="iptables -P FORWARD ACCEPT`n"
    $replaceNet +="iptables -P POSTROUTING ACCEPT`n"
    $replaceNet +="iptables -t nat -F`n"
    $replaceNet +="iptables -t mangle -F`n"
    $replaceNet +="iptables -F`n"
    $replaceNet +="iptables -X`n"
    $replaceNet +="iptables -t nat -A POSTROUTING -s $($avnNets[0]) -o eth0.$($mgmtVlanId) -j SNAT --to-source $CloudBuilderIP`n"
    $replaceNet +="iptables -t nat -A POSTROUTING -s $($avnNets[1]) -o eth0.$($mgmtVlanId) -j SNAT --to-source $CloudBuilderIP`n"
    $replaceNet +="iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT`n"
    $replaceNet +="iptables-save > /etc/systemd/scripts/ip4save`n"
    $replaceNet +="sed -i '/# End/q' /etc/systemd/scripts/iptables`n"
    $replaceNet +="systemctl restart iptables`n"
    $replaceNet +="systemctl start nfs-server`n"

    $replaceNet +="END`n"


    logger "Creating bash script to: Backup NIC, DHCP and NTP config files on CB"
    logger "Setting CB IP address to $CloudBuilderIP"
    logger "Configuring and enabling DHCP for subnet $DhcpIPSubnet"
    logger "Configuring NTP and NFS server"

    logger $replaceNet

    logger "The following DNS will be setup:"
    logger ($dnsIPFQDNs | Out-String)

    #CB DNS setup

    $dnsZoneBuilder =""

    foreach ($vmFQDN in $dnsIPFQDNs.GetEnumerator()) {

        $dnsZoneBuilder+="echo $($vmFQDN.Name).$vcfDomainname. FQDN4 $($vmFQDN.Value)`n"

    }
    $bgpNeighborPass = $($global:bringUpOptions | Select -ExpandProperty nsxtSpec | Select -ExpandProperty nsxtEdgeSpec | Select -ExpandProperty bgpNeighbours).password
    $bgpLocalASInfo = $($global:bringUpOptions | Select -ExpandProperty nsxtSpec | Select -ExpandProperty nsxtEdgeSpec).asn
    $esgIPs = $($global:bringUpOptions |  Select -ExpandProperty nsxtSpec | Select -ExpandProperty nsxtEdgeSpec | Select -ExpandProperty edgeNodeSpecs | Select -ExpandProperty interfaces | Select interfaceCidr | foreach -Process {$_.interfaceCidr.Split("/")[0]})
   
    #add CB to Zone - LogInsight was waiting ~30 seconds on a ssh try to resolve it and bringup was failing because of this

    $addDNSRecords = Get-Content "$scriptDir\additional_DNS_Entries.txt"

    foreach($dnsRcd in $addDNSRecords) {

        $dnsZoneBuilder+="echo $dnsRcd`n"

    }

    $dnsZoneBuilder+="echo $CBname.$vcfDomainname. FQDN4 $CloudBuilderIP`n"

    #/etc/mararc & db zone file builder + BGP Daemon config

    $replaceDNS =""
    $replaceDNS +="`n"
    $replaceDNS +="echo $($userOptions.masterPassword) | sudo su - <<END`n"
    $replaceDNS +="(`n"
    $replaceDNS +="echo hide_disclaimer = \`"Yes\`"`n"
    $replaceDNS +="echo ipv4_bind_addresses = \`"127.0.0.1\`"`n"
    $replaceDNS +="echo chroot_dir = \`"/etc/maradns\`"`n"
    $replaceDNS +="echo timeout_seconds = 2`n"
    $replaceDNS +="echo csv2 = {}`n"
    $replaceDNS +="echo csv2[\`"$vcfDomainName.\`"] = \`"db.$vcfDomainName\`"`n"
    $replaceDNS +=")> /etc/mararc`n"
    $replaceDNS +="(`n"
    $replaceDNS +="echo bind_address = \`"$CloudBuilderIP\`"`n"
    $replaceDNS +="echo chroot_dir = \`"/etc/maradns\`"`n"
    $replaceDNS +="echo upstream_servers = {}`n"
    #You can change upstream DNS in the line below!  VVVVVVVVVVVVVVVV
    $replaceDNS +="echo upstream_servers[\`".\`"]=\`"8.8.8.8, 8.8.4.4\`"`n"
    $replaceDNS +="echo upstream_servers[\`"$reverseDNS\`"] = \`"127.0.0.1\`"`n"
    $replaceDNS +="echo upstream_servers[\`"$revRegionDNS\`"] = \`"127.0.0.1\`"`n"
    $replaceDNS +="echo upstream_servers[\`"$revxRegionDNS\`"] = \`"127.0.0.1\`"`n"
    $replaceDNS +="echo upstream_servers[\`"$vcfDomainName.\`"] = \`"127.0.0.1\`"`n"
    $replaceDNS +="echo recursive_acl = \`"$CloudBuilderIPSubnet/$CloudBuilderCIDR,$regionSubnet,$xregionSubnet\`"`n"
    $replaceDNS +="echo filter_rfc1918 = 0`n"
    $replaceDNS +=")> /etc/dwood3rc`n"
    $replaceDNS +="(`n"
    $replaceDNS +="$dnsZoneBuilder`n"
    $replaceDNS +=")> /etc/maradns/db.$vcfDomainName`n"
    $replaceDNS +="chmod 644 /etc/maradns/db.$vcfDomainName`n"
    $replaceDNS +="(`n"
    $replaceDNS +="echo [Unit]`n"
    $replaceDNS +="echo SourcePath=/etc/rc.d/init.d/maradns`n"
    $replaceDNS +="echo Description=MaraDNS is secure Domain Name Server`n"
    $replaceDNS +="echo After=network-online.target`n"
    $replaceDNS +="echo `n"
    $replaceDNS +="echo [Service]`n"
    $replaceDNS +="echo RemainAfterExit=yes`n"
    $replaceDNS +="echo ExecStart=/etc/rc.d/init.d/maradns start`n"
    $replaceDNS +="echo ExecStop=/etc/rc.d/init.d/maradns stop`n"
    $replaceDNS +="echo `n"
    $replaceDNS +="echo [Install]`n"
    $replaceDNS +="echo WantedBy=multi-user.target`n"
    $replaceDNS +=")> /etc/systemd/system/maradns.service`n"
    $replaceDNS +="(`n"
    $replaceDNS +="echo [Unit]`n"
    $replaceDNS +="echo SourcePath=/etc/rc.d/init.d/maradns.deadwood`n"
    $replaceDNS +="echo Description=MaraDNS.Deadwood is Recursive DNS`n"
    $replaceDNS +="echo After=network-online.target`n"
    $replaceDNS +="echo `n"
    $replaceDNS +="echo [Service]`n"
    $replaceDNS +="echo RemainAfterExit=yes`n"
    $replaceDNS +="echo ExecStart=/etc/rc.d/init.d/maradns.deadwood start`n"
    $replaceDNS +="echo ExecStop=/etc/rc.d/init.d/maradns.deadwood stop`n"
    $replaceDNS +="echo `n"
    $replaceDNS +="echo [Install]`n"
    $replaceDNS +="echo WantedBy=multi-user.target`n"
    $replaceDNS +=")> /etc/systemd/system/maradns.deadwood.service`n"
    $replaceDNS +="(`n"
    $replaceDNS +="echo [Unit]`n"
    $replaceDNS +="echo Description=GoBGPd BGP Daemon`n"
    $replaceDNS +="echo After=network.target`n"
    $replaceDNS +="echo Wants=network.target`n"
    $replaceDNS +="echo [Service]`n"
    $replaceDNS +="echo ExecStart=/bin/bash -c `\`"/usr/bin/gobgpd -f /usr/bin/gobgpd.conf`\`"`n"
    $replaceDNS +="echo TimeoutStartSec=0`n"
    $replaceDNS +="echo ExecStop=`n"
    $replaceDNS +="echo Restart=always`n"
    $replaceDNS +="echo RestartSec=30`n"
    $replaceDNS +="echo [Install]`n"
    $replaceDNS +="echo WantedBy=multi-user.target`n"
    $replaceDNS +=") > /etc/systemd/system/gobgpd.service`n"
    $replaceDNS +="(`n"
    $replaceDNS +="echo [global.config]`n"
    $replaceDNS +="echo   as = $($bgpNeighborInfo[0].autonomousSystem)`n"
    $replaceDNS +="echo   router-id = `\`"$CloudBuilderIP`\`"`n"
    $replaceDNS +="echo [[neighbors]]`n"
    $replaceDNS +="echo   [neighbors.config]`n"
    $replaceDNS +="echo     neighbor-address = `\`"$($esgIPs[0])`\`"`n"
    $replaceDNS +="echo     peer-as = $($bgpLocalASInfo)`n"
    $replaceDNS +="echo     auth-password = `\`"$($bgpNeighborPass[0])`\`"`n"
    $replaceDNS +="echo [[neighbors]]`n"
    $replaceDNS +="echo   [neighbors.config]`n"
    $replaceDNS +="echo     neighbor-address = `\`"$($esgIPs[1])`\`"`n"
    $replaceDNS +="echo     peer-as = $($bgpLocalASInfo)`n"
    $replaceDNS +="echo     auth-password = `\`"$($bgpNeighborPass[1])`\`"`n"
    $replaceDNS +="echo [[neighbors]]`n"
    $replaceDNS +="echo   [neighbors.config]`n"
    $replaceDNS +="echo     neighbor-address = `\`"$($esgIPs[2])`\`"`n"
    $replaceDNS +="echo     peer-as = $($bgpLocalASInfo)`n"
    $replaceDNS +="echo     auth-password = `\`"$($bgpNeighborPass[0])`\`"`n"
    $replaceDNS +="echo [[neighbors]]`n"
    $replaceDNS +="echo   [neighbors.config]`n"
    $replaceDNS +="echo     neighbor-address = `\`"$($esgIPs[3])`\`"`n"
    $replaceDNS +="echo     peer-as = $($bgpLocalASInfo)`n"
    $replaceDNS +="echo     auth-password = `\`"$($bgpNeighborPass[1])`\`"`n"
    $replaceDNS +="echo ) > /usr/bin/gobgpd.conf`n"
    $replaceDNS +="echo net.ipv4.ip_forward = 1 >> /etc/sysctl.conf`n"
    $replaceDNS +="echo `"@reboot root /bin/sleep 5 && /sbin/sysctl --system`" > /etc/cron.d/sysctl`n"
    $replaceDNS +="echo `"@reboot root /bin/sleep 5 && gobgp global rib add $CloudBuilderIPSubnet/$CloudBuilderCIDR -a ipv4`" > /etc/cron.d/gobgpd-route`n"
    $replaceDNS +="echo `"@reboot root /bin/sleep 5 && gobgp global rib add 0.0.0.0/0 -a ipv4`" >> /etc/cron.d/gobgpd-route`n"
    $replaceDNS +="echo nsxt.manager.wait.minutes=45 >> /etc/vmware/vcf/bringup/application.properties`n"
    $replaceDNS +="chkconfig gobgpd on`n"
    $replaceDNS +="chkconfig maradns on`n"
    $replaceDNS +="chkconfig maradns.deadwood on`n"
    $replaceDNS +="systemctl disable sendmail`n"
    $replaceDNS +="systemctl mask vami-sfcb`n"
    $replaceDNS +="shutdown -r`n"
    $replaceDNS +="END`n"

    logger "Configuring DNS server and Rebooting CloudBuilder"

    logger $replaceDNS

    $cbConfig = $replaceNet + $replaceDNS

    bytewriter $cbConfig "CBConfig.bash"

    Copy-VMGuestFile -Server $($userOptions.esxhost) -Source "$scriptDir\Temp\CBConfig.bash" -Destination "/home/admin/" -LocalToGuest -VM $CBName -HostUser $($userOptions.username) -HostPassword $($userOptions.password) -GuestUser admin -GuestPassword $($userOptions.masterPassword) -Force
 
    Copy-VMGuestFile -Server $($userOptions.esxhost) -Source "$scriptDir\maradns-2.0.16-1.x86_64.rpm" -Destination "/home/admin/" -LocalToGuest -VM $CBName -HostUser $($userOptions.username) -HostPassword $($userOptions.password) -GuestUser admin -GuestPassword $($userOptions.masterPassword) -Force

    Copy-VMGuestFile -Server $($userOptions.esxhost) -Source "$scriptDir\gobgp-2.9.0-2.ph3.x86_64.rpm" -Destination "/home/admin/" -LocalToGuest -VM $CBName -HostUser $($userOptions.username) -HostPassword $($userOptions.password) -GuestUser admin -GuestPassword $($userOptions.masterPassword) -Force

    Invoke-VMScript -ScriptType Bash -Server $($userOptions.esxhost) -GuestUser root -GuestPassword $($userOptions.masterPassword) -VM $CBName -HostUser $($userOptions.username) -HostPassword $($userOptions.password) -ScriptText "rpm -i /home/admin/maradns-2.0.16-1.x86_64.rpm;rpm -i /home/admin/gobgp-2.9.0-2.ph3.x86_64.rpm;chmod 777 /home/admin/CBConfig.bash;/home/admin/CBConfig.bash"

    do {
	      logger "Waiting for CloudBuilder Network to be available..."
	      sleep 60      
	    } until(Test-NetConnection $CloudBuilderIP -Port 22 | ? { $_.tcptestsucceeded } )

    do {
          $CBOnline = Get-VM -Name $CBName
	      logger "Waiting for CloudBuilder VMTools to be started"
	      sleep 30  
        } until($CBOnline.ExtensionData.Guest.ToolsRunningStatus -eq "guestToolsRunning")   

    logger "CloudBuilder online!"

    #Restart DHCP server as it never seems to want to start the first time
    If($($userOptions.mgmtNetGateway) -ne 0) {
        $cbDhcpSvc = "dhcpd4@eth0.$($userOptions.mgmtNetVlan)"
    } else {
        $cbDhcpSvc = "dhcpd4@eth0"
    }
    Invoke-VMScript -ScriptType Bash -Server $($userOptions.esxhost) -GuestUser root -GuestPassword $($userOptions.masterPassword) -VM $CBName -HostUser $($userOptions.username) -HostPassword $($userOptions.password) -ScriptText "systemctl restart $cbDhcpSvc"

}
Function CIDRtoSubnet ($inputCIDR) 
{

    (('1'*$inputCIDR+'0'*(32-$inputCIDR)-split'(.{8})')-ne''|%{[convert]::ToUInt32($_,2)})-join'.'

}
Function SubnettoCIDR ($inputSubnetMask) 
{

    ((([IPAddress]$inputSubnetMask).getaddressbytes() | %{[CONVERT]::ToString($_,2)} | Out-String) -replace "[\s0]").length

}
Function parseBringUpFile
{ 
    $bringupObject = $global:bringUpOptions
    #Get VLAN's and network types from EMS JSON Data
    $baseNetworkInfo = New-Object System.Collections.Hashtable
    $bringupObject.networkSpecs | Select NetworkType,VLANId | foreach -Process {$baseNetworkInfo+=@{$_.NetworkType=$_.VLANId}}
    $baseNetworkInfo +=@{"HOSTTEP"=$($bringupObject.nsxtSpec | Select -ExpandProperty transportVlanId)}
    #Get Additional Data from EMS JSON Data
    $txtDomainName.text = $bringupObject.dnsSpec.subdomain
    $txtMgmtNet.text = $($bringupObject.networkSpecs| where { $_.networkType -eq "MANAGEMENT" } | Select subnet).subnet
    $txtMgmtNetVlan.text = $baseNetworkInfo['MANAGEMENT']
    $txtMgmtGateway.text = $($bringupObject.networkSpecs| where { $_.networkType -eq "MANAGEMENT" } | Select gateway).gateway
    $txtMasterPass.text = $($bringupObject.hostSpecs| Select-Object @{N="password";E={$_.credentials.password}} -unique).password
    $txtNTP.text = $bringupObject.ntpServers
    $txtDNS.text = $bringupObject.dnsSpec.nameServer
    If ($global:Ways -ilike "internalsvcs") {
        $txtCBIP.text = $bringupObject.ntpServers
    }
    $txtMasterPass.enabled = $false
    $txtNTP.enabled = $false
    $txtDNS.enabled = $false
    if ($global:Ways -match "externalsvcs"){
        $txtCBIP.enabled = $true
        $txtMgmtNetVlan.enabled = $true
    } else {
        $txtCBIP.enabled = $false
        $txtMgmtNetVlan.enabled = $false
    }
    $txtMgmtNetVlan.enabled =$false
    $txtMgmtGateway.enabled = $false
    $txtDomainName.enabled = $false
    $txtMgmtNet.enabled = $false
   }
Function compileDNSRecords
{

    $dnsFQDNs = New-Object System.Collections.Hashtable

    #Hosts from template file
    $global:bringUpOptions | Select -ExpandProperty hostSpecs | ForEach-Object -Process {$dnsFQDNs.Add($_.hostname,$_.ipAddressPrivate.ipAddress)}
    #Additional Hosts
    if ($jsonLoc -ne "") {

        Get-Content -raw $jsonLoc | ConvertFrom-Json | Select -ExpandProperty genVM | ForEach-Object -Process {$dnsFQDNs.Add($_.name,$_.mgmtIP)}

    }
    #vCenter
    $global:bringupOptions | Select -ExpandProperty vCenterSpec | ForEach-Object -Process {$dnsFQDNs.add($_.vcenterHostName,$_.vcenterIP)}
    #SDDC Manager
    $global:bringupOptions | Select -ExpandProperty sddcManagerSpec | ForEach-Object -Process {$dnsFQDNs.add($_.hostname,$_.ipAddress)}
    #NSX
    $global:bringupOptions | Select -ExpandProperty nsxtSpec | Select vipFQDN, vip | ForEach-Object -Process {$dnsFQDNs.add($_.vipFqdn,$_.vip)}
    $global:bringupOptions | Select -ExpandProperty nsxtSpec | Select -ExpandProperty nsxtManagers | ForEach-Object -Process {$dnsFQDNs.add($_.hostname,$_.ip)}

#    $global:bringupOptions | Select -ExpandProperty nsxtSpec | ForEach-Object -Process {$dnsFQDNs.add($_.nsxManagerHostName,$_.nsxManagerIp)}
    #PSC
#    $global:bringupOptions | Select -ExpandProperty pscSpecs | ForEach-Object -Process {$dnsFQDNs.add($_.pscHostName,$_.pscIP)}

    return $dnsFQDNs

}
function setFormControls ($formway)
{

    switch ($formway)
    {
        'externalsvcs' {
                        $global:Ways = "externalsvcs"
                        $pnlWaysPanel.Visible = $false

                        $lblBringUpFile.Enabled = $true
                        $txtBringUpFile.Enabled = $true
                        $lblBringUpFile.visible = $true
                        $txtBringUpFile.visible = $true
                        $txtBringUpFile.Text = ""

                        $lblMgmtNetVLAN.Enabled = $false
                        $txtMgmtNetVLAN.Enabled = $false

                        $lblMgmtNet.Enabled = $false
                        $txtMgmtNet.Enabled = $false
                        $lblMgmtNet.visible = $true
                        $txtMgmtNet.visible = $true                       

                        $lblLabGateway.Enabled = $true
                        $txtLabGateway.Enabled = $true
                        $lblLabGateway.Visible = $false
                        $txtLabGateway.Visible = $false

                        $lblMgmtGateway.Enabled = $false
                        $txtMgmtGateway.Enabled = $false
                        $lblMgmtGateway.visible = $true
                        $txtMgmtGateway.visible = $true

                        $lblCBIP.Enabled = $true
                        $txtCBIP.Enabled = $true
                        $lblCBIP.visible = $true
                        $txtCBIP.visible = $true   
  
                        $lblCBLoc.Enabled = $true
                        $txtCBLoc.Enabled = $true
                        $lblCBLoc.visible = $true
                        $txtCBLoc.visible = $true  
                        
                        $txtNestedJSON.Enabled = $true
                        $lblNestedJSON.Enabled = $true
                        $txtNestedJSON.Text = "" 

                        $chkUseCBISO.Checked = $true
                        $lblvSphereLoc.Enabled = $false
                        $txtvSphereLoc.Enabled = $false

                        $txtMasterPass.Enabled = $false
                        $lblMasterPass.Enabled = $false

                        $lblDNS.Enabled = $false
                        $txtDNS.Enabled = $false

                        $lblNTP.Enabled = $false
                        $txtNTP.Enabled = $false

                        $txtDomainName.enabled = $false
                        $lblDomainName.Enabled = $false

                        $chkSb.Enabled = $true
                        $chkSb.Checked = $true
 
                        $chkHostOnly.Checked = $false
                        $chkHostOnly.Enabled = $false

                        $chkInternalSvcs.Enabled = $false
                        $chkInternalSvcs.Checked = $false

                        $btnExpert.Visible = $false
        }
        'internalsvcs' {
                        $global:Ways = "internalsvcs"
                        $pnlWaysPanel.Visible = $false

                        $lblBringUpFile.Enabled = $true
                        $txtBringUpFile.Enabled = $true
                        $lblBringUpFile.visible = $true
                        $txtBringUpFile.visible = $true
                        $txtBringUpFile.Text = "$scriptDir\AUTOMATED_AVN_VCF_VLAN_10-13_NOLIC_v41.json"

                        $lblMgmtNetVLAN.Enabled = $false
                        $txtMgmtNetVLAN.Enabled = $false

                        $lblMgmtNet.Enabled = $false
                        $txtMgmtNet.Enabled = $false
                        $lblMgmtNet.visible = $true
                        $txtMgmtNet.visible = $true

                        $lblLabGateway.Enabled = $true
                        $txtLabGateway.Enabled = $true
                        $lblLabGateway.Visible = $true
                        $txtLabGateway.Visible = $true

                        $lblMgmtGateway.Enabled = $false
                        $txtMgmtGateway.Enabled = $false
                        $lblMgmtGateway.visible = $true
                        $txtMgmtGateway.visible = $true

                        $lblCBIP.Enabled = $false
                        $txtCBIP.Enabled = $false
                        $lblCBIP.visible = $true
                        $txtCBIP.visible = $true

                        $lblCBLoc.Enabled = $true
                        $txtCBLoc.Enabled = $true
                        $lblCBLoc.visible = $true
                        $txtCBLoc.visible = $true

                        $txtNestedJSON.Enabled = $true
                        $lblNestedJSON.Enabled = $true
                        $txtNestedJSON.Text = ""

                        $chkUseCBISO.Checked = $true
                        $lblvSphereLoc.Enabled = $false
                        $txtvSphereLoc.Enabled = $false

                        $txtMasterPass.Enabled = $false
                        $lblMasterPass.Enabled = $false

                        $lblDNS.Enabled = $false
                        $txtDNS.Enabled = $false

                        $lblNTP.Enabled = $false
                        $txtNTP.Enabled = $false

                        $txtDomainName.enabled = $false
                        $lblDomainName.Enabled = $false

                        $chkSb.Enabled = $true
                        $chkSb.Checked = $true
 
                        $chkHostOnly.Checked = $false
                        $chkHostOnly.Enabled = $false
                        
                        $chkInternalSvcs.Enabled = $false
                        $chkInternalSvcs.Checked = $true
                        
                        $btnExpert.Visible = $false

                        $global:bringUpOptions = Get-Content -Raw $($txtBringUpFile.Text)  | ConvertFrom-Json  
                        parseBringUpFile

        }
        'expansion'    {
                        $global:Ways = "expansion"
                        $pnlWaysPanel.Visible = $false
                        $lblBringUpFile.Enabled = $false
                        $txtBringUpFile.Enabled = $false
                        $lblBringUpFile.visible = $false
                        $txtBringUpFile.visible = $false

                        $lblMgmtNetVLAN.Enabled = $true
                        $txtMgmtNetVLAN.Enabled = $true

                        $lblMgmtNet.Enabled = $false
                        $txtMgmtNet.Enabled = $false
                        $lblMgmtNet.visible = $false
                        $txtMgmtNet.visible = $false
   
                        $lblLabGateway.Enabled = $false
                        $txtLabGateway.Enabled = $false
                        $lblLabGateway.Visible = $false
                        $txtLabGateway.Visible = $false  
   
                        $lblMgmtGateway.Enabled = $false
                        $txtMgmtGateway.Enabled = $false
                        $lblMgmtGateway.visible = $false
                        $txtMgmtGateway.visible = $false

                        $lblCBIP.Enabled = $false
                        $txtCBIP.Enabled = $false
                        $lblCBIP.visible = $false
                        $txtCBIP.visible = $false

                        $lblCBLoc.Enabled = $false
                        $txtCBLoc.Enabled = $false
                        $lblCBLoc.visible = $false
                        $txtCBLoc.visible = $false

                        $txtNestedJSON.Enabled = $true
                        $lblNestedJSON.Enabled = $true
                        $txtNestedJSON.Text = ""

                        $chkUseCBISO.Enabled = $false
                        $chkUseCBISO.Checked = $false
                        $lblvSphereLoc.Enabled = $true
                        $txtvSphereLoc.Enabled = $true

                        $txtMasterPass.Enabled = $true
                        $lblMasterPass.Enabled = $true

                        $lblDNS.Enabled = $true
                        $txtDNS.Enabled = $true

                        $lblNTP.Enabled = $true
                        $txtNTP.Enabled = $true

                        $txtDomainName.enabled = $true
                        $lblDomainName.Enabled = $true

                        $chkSb.Enabled = $false
                        $chkSb.Checked = $false
                        $chkSb.Visible = $false

                        $chkHostOnly.Checked = $true
                        $chkHostOnly.Enabled = $true

                        $chkInternalSvcs.Enabled = $false
                        $chkInternalSvcs.Checked = $false
                        
                        $btnExpert.Visible = $false

                        $lblConflictWarning.Visible = $false
        }
        'enableall'     {

                        $pnlWaysPanel.Visible = $false
                        $btnExpert.Visible = $false
                        $lblDNS.Enabled = $true
                        $lblNTP.Enabled = $true
                        $txtDNS.Enabled = $true
                        $txtNTP.Enabled = $true
                        $chkInternalSvcs.Enabled = $true
                        $chkSb.Enabled = $true
                        $chkInternalSvcs.Checked = $false
                        $chkSb.Checked = $false
                        $chkHostOnly.Enabled = $true
                        $lblCBLoc.Enabled = $true
                        $txtCBLoc.Enabled = $true
                        $lblCBIP.Enabled = $true
                        $txtCBIP.Enabled = $true
                        $lblMgmtNet.Enabled = $true
                        $txtMgmtNet.Enabled = $true
                        $lblMgmtGateway.Enabled = $true
                        $txtMgmtGateway.Enabled = $true
                        $txtNestedJSON.Enabled = $true
                        $lblNestedJSON.Enabled = $true
                        $lblBringupFile.Enabled = $true
                        $txtBringupFile.Enabled = $true
                        #$lblConflictWarning.Visible = $true

        }


    }
}
function convert64Img ($imgAs64)
{

        $imageBytes = [Convert]::FromBase64String($imgAs64)
        $ms = New-Object IO.MemoryStream($imageBytes, 0, $imageBytes.Length)
        $ms.Write($imageBytes, 0, $imageBytes.Length);
        $imageAsImage = [System.Drawing.Image]::FromStream($ms, $true)

        return $imageAsImage

}
function configDrsHACluster ($cluster){  
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx  
    $spec.dasConfig = New-Object VMware.Vim.ClusterDasConfigInfo  
    $spec.dasConfig.vmMonitoring = "vmMonitoringDisabled"  
    $spec.drsConfig = New-Object VMware.Vim.ClusterDrsConfigInfo
    $spec.drsConfig.vmotionRate = 5
    $cluster.ExtensionData.ReconfigureComputeResource($spec, $true)  
}
#endregion Functions

#region CLI mode - Deprecated

#endregion CLI Mode

#region Begin Main Form
#Clean Temp / Initialize Log and logging window
try {
If (Test-Path "$scriptDir\Temp"){Remove-Item "$scriptDir\Temp" -Recurse -Force -Confirm:$False -ErrorAction:Stop}
} catch {
    $errMsg = ($_.Exception.Message).Split("`t")
    logger $errMsg
    logger "Please close any files that are open or mounted in the $scriptDir\Temp folder"
    exit
}
logger $welcomeText -logOnly
Start-Process powershell -Argumentlist "`$host.UI.RawUI.WindowTitle = 'VLC Logging window';Get-Content '$logfile' -wait"
#Setup help for form

$tooltips = New-Object System.Windows.Forms.ToolTip
$tooltips.IsBalloon = $true

$ShowTips={
    #display popup help
    #each value is the name of a control on the form. 
     Switch ($this.name) {
        #User Settings
        "btnWay2" {$tip = "Using the VLC in this mode assumes that you will provide the required external `nservices for your lab and you will point the VLC and the JSON config file to these services."}
        "btnWay1" {$tip = "Using this mode means VLC will build all the `nrequired services for VCF."}
        "btnWay3" {$tip = "Using `"Way 3`" assumes you have already built a VCF lab with the VLC and you want `nto expand it with more virtual hosts!  `nThis is awesome news and the VLC can help you level up."}
        "txtDomainName"  {$tip = "Enter the name FQDN you will use for the VCF deployment."}
        "txtMgmtNet" {$tip = "Enter the management network CIDR X.X.X.X/XX"}
        "txtMgmtNetVlan" {$tip = "Virtual Infrastructure VLAN 0-4094 - Will be used for Mgmt, vSAN, vMotion and Host TEP subnets provided they are all set the same in EMS JSON"}
        "txtMgmtGateway" {$tip = "Enter the gateway for the management network, MUST be accessiable!"}
        "txtMasterPass" {$tip = "Enter the password that will be used for Cloud Builder if deployed by VLC and/or `nnested hosts if VCF EMS JSON is not populated"}
        "txtNestedJSON" {$tip = "Click to select the path where the JSON file for creating additional nested hosts resides"}
        "txtCBLoc" {$tip = "Click to select the path where the CloudBuilder OVA resides"}
        "txtCBIP" {$tip = "Enter the IP address for CloudBuilder, this must be an IP address on the `nmanagement network entered above"}
        "txtvSphereLoc" {$tip = "Click to select the path where the vSphere ISO resides"}
        "txtVMPrefix" {$tip = "If desired, enter a prefix for the created nested hosts and CloudBuilder VMs "}
        "txtBringupFile" {$tip = "Click to select the path where the VCF-EMS JSON file resides"}
        "txtNTP" {$tip = "Enter the IP addres of your NTP server"}
        "txtDNS" {$tip = "Enter the IP addres of your DNS server"}
        "txtLabGateway" {$tip = "This is external access for the lab and will be set as the default gateway for CloudBuilder`n It must reside on the same subnet as your MGMT net."}
        "chkHostOnly" {$tip = "When this box is checked, VLC will only create hosts and will not import CloudBuilder"}
        "chkEC" {$tip = "When this box is checked, VLC will add VLAN interfaces to CloudBuilder according to EMS JSON, `nwithout a check it will place everything on VLAN 0"}
        "chkSb" {$tip = "When this box is checked the field for the VCF-EMS JSON will be displayed, `nafter deploying the nested hosts and CloudBuilder, VLC will continue by submitting the JSON and starting bringup"}
        "chkInternalSvcs" {$tip = "When this box is checked VLC will import Cloud Builder and `nconfigure it as a DNS, NTP and DHCP server with the information from the VCF-EMS JSON file"}
        #Infrastructure Settings
        "txtHostIP" {$tip = "This can be an IP address or FQDN of a single host, or a vCenter"}
        "txtUsername" {$tip = "Enter the username for the host or vCenter"}
        "txtPassword" {$tip = "Enter the password for the username above (SSO username should be 'username@domain.xxx'"}
        "listCluster" {$tip = "Select the cluster to deploy VCF in.  If you entered a vCenter above and have cluster(s)`n configured this list will be populated and you can select a cluster"}
        "listNetName" {$tip = "Select the portgroup to deploy VCF on.  This list will only be populated with portgroups `nthat have the required pre-requesite security features set to accept.  Make sure your jumphost has a NIC and IP `naddress attached to this portgroup!"}
        "listDatastore" {$tip = "Select the datastore to deploy VCF to"}
      }
     $tooltips.SetToolTip($this,$tip)
} #end ShowHelp

      $sbLoadSettings = {
        $iniFilename = Get-FileName "$scriptDir" "INI (*.ini)| *.ini" "load"
        $setContent = Get-IniContent $iniFilename
        UnLockFormFields
        SetFormValues $setContent
        If ($txtBringupFile.Text -notlike "") {
            $global:bringUpOptions = Get-Content -Raw $($txtBringUpFile.Text)  | ConvertFrom-Json
            parseBringupFile
            }
        $pnlWaysPanel.Visible = $false
      }

      $sbSaveSettings = {
        $outIniFile = Get-FileName "$scriptDir" "INI (*.ini)| *.ini" "save"
        $outIniData = GetFormValues $getContent "Get"
        Out-IniFile $outIniData $outIniFile
      }

      $sbExit = {
        $global:isExit = $true
        $frmVCFLCMain.Close()
      }

$formLogo =@"
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
"@
$way1Img =@"
/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCACMAJIDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD6VooooICiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigArrfhT/yP2l/9tf8A0U9clXW/Cn/kftL/AO2v/op6BmP+0B8c/iL4P8Xalon2Jfhj4GhgV4fiPc2Dayt2xVCY0RP3GnkMWXzr0mPvsIrw/wCFnx9+MHhfVvGq6D4e1vxzptzqNnM+satq7eKhZeZp8Uqxxx6auCkxdpA8KpCgGzGSMfRf7VP7TegfCnwnrOiaT450nQ/iGr2AitZkW4mtoZ7qJJJjCeG2wGWTB7LnpXz5pPxe8K/BHVdP1Hwj8e/B+s22p+JrD/hIdJ0nwpYWAuYJZkS5uJZIAGDJEWcv7ZPWgo+nPhL8RvGvxJ+FfjC98a+FX8MXVq1xbWjNaXFmL6H7MrmUW9wBLHtd3j+bhvL3Dg184/Hrx7rXw58Atqnh+Oxl1SS8t7SIajG7wgyyqmWCMp43djX2DY/ETwz8UPhprOt+Etcs/EGkm3urf7XYyb0EiIQyH0I44PrXxD+1R/yTS0/7DWnf+lMdAiFL7496bGbme08Da6gG77LaLdWch+jvJIM/UCuo+FnxetfiO2pafcaddaB4k0pxHf6RegCSIkZDKRw6Hsw4rvYf9TH/ALo/lXhviBP7L/bB8LPZrsOp+G7sXwUD5xHKnllu/G5gPrQIqa9+0RrfhX9oK68Lalpdp/wg8MdtHLq0asJra4n3eX5hL7ShK44UYyK98lk227yKQcKWHp0rwK18Jaf47+N3xb0DVYvOsL7StPjkXuOJMMPQg4IPqK6L4L+K9Qt7fWPAHiSVpPEfhtBGtxIP+P20IPkzA9ztGG9x0FAG18KviZc+Lfh3eeJNcW2tfstxdpJ9lRlQRxSMoOGYnOF55rltN+IHxT+JGnQ634M0fw7pnh+4AltJteeaSe7j552RlRGDwQSW6n5af+znpMGu/BjUNOuQTb3d/qEEm04O1pnBx+dY2g6t40/Zx0uLRtb0l/FfgSwXZaazpi7ru1gHIWeLOW2jjcvp0oA9l8D6h4g1HQY5PE+m2+l6wrMk0NnMZYTg8MjEAkEevNb9ZPhTxZpPjjw/Z63ol7HqGmXiCSGeI8MD/I+1a1AgooooAKKKKACiiigAqh4m8dah8MfB3irxfpKW8mqaFoWpajapdIXiMsVpK6B1BBK5UZAIq/UlvcS2sgkgleGTBXfGxU4IIIyPUEj8aBnmfij4yS/Cu+8XfEDQP2nPg54o8Q+IZ9ItLrS7fTYseXHMtsJIwursVCRzvK+QQRH1UZIk1T41XHwlvtX1zQP2n/g54kvPGXinT5NTgj02Ii0EkdrYvcqF1ckRRQwJIwP91iWUdPT/AO1r7/n8uP8Av63+NH9rX3/P5cf9/W/xoHc4Hwj8RT4B8RW3h/Qfjn8Nvila+OvEWrXeq6T4dskS9tmm068unnRk1GfbEsltEmGjP+tALZxnj/2rPMX4WJNHb3Fz5GqWM7x20LSybEnRmIVQScAHoK9u/ta+ww+2XGGUqf3rcgggjr0IJH41UIB6jNAjx+1/aZ8N6jCItH0jxJqt7twtuNEuYMnHTdKigfWrPwv8G6/qHi/VPH3i+3Sx1a9iW1sNLRw/2G1BJAZgSC7E5bHHQdq9WCqOgA/CloA8e8DWdxF+0d8Rbh4JEt5LGwVJWQhHID5APQ4yPzqf47eEtQijsvHnhm3afxN4eV2+zR4BvrVh+9gPrkDI56gV61gZzjmigDw79m/Ur+z+BM+qR6PdC9a5vLuPTJkMcx3SM4TDYwSDjmtKP9pbQJIzbXHh/wATQaqVwdNfR5mJb03hSn616+AF6DFJtGc4GfpQB5T+zn4P1Pwn4S1STU7I6U2q6pcajDpxYH7NHI5KqcdDjkjsTXq9FFABRRRQIKKKKACiiigAoorovh9pNrrni6wsr2Lz7WXzN8e4rnEbEcgg9QKAOdora8efFH4e6H421zwJ4P8ACF7498faLbi61LS7W8eytdMiKK6y3V3M4VU2sDiFZn/2Ca8g+GX7WXgS81zxLpPi3T9P1zU47uM6PZ+BIb+YPaG2jlld5Lp494jeRYy5WIseRHjOAdj0Wiu58B698O/i54L8Vap4c0i/sLzQ2ktbq11MSRT20/2dZ0yBIysCkkbAgkc4PIIr52/aN8XeIPBfw3e+8Lzw2+tSXttawSXCB48yyqnzD0+agD1CivPvgr8SJfiF4ZlTUohaeJNJmNjq1pjHlzqOWH+yw+YH0NUfFPjrVtL+Pngrwtbyoukappl9dXMZQFmeJogmD2Hzn9KBHp9FeU+O/D/xFtI9b1XSvHNrZ2USSXEFnJpayFFAJCFtwz9a5v4MN8TPiF4F8K+Lb3xvaRw6nbxXk1imlL908lA27070DPeqK8W8Xa1411v41P4U8P8AiKDQrGLSVvmaSyWcs5kK4GSMVB/wnnjb4VeOvDei+Nr3T9f0TxHcmxs9Us7c28sFxtLKkibiCGAPI9KAPcKKKKBBRRRQAUUUUAFFFFABXW/Cn/kftL/7a/8Aop65KrNp48svhbDqXjHUoLi60/QdNvdTuILUKZZI4baR2VNxA3ELgZIFAz0X9qnRfBy/DK48TeJ/A8HjK90ue1h0xY5vsV9FPcXUMEZt71cSWx3yqS6MCADXhXhvwnqnw2vzD8TvhBd+LNC8YeJ9LtJNQ8Z+I9O157Gd1jsbZlT7OGk2qVUu5MhHVick5vxX0+91Hxr408c/Fv4G+Pr/AMH3f9jWWlWUXi2xiSzlEghO6G31RVJe4lgKthsEbiVxmsS6+HNj4N1LW7zx/wDAP4j3mi6t4nsYPDEDePIZTaNLFbQwwtjWOJDdiaQOc7fNB3qBgBR9tzeDdB8C/D/WtL8OaHpvh7TfstxL9i0qzjtYd7Rnc2yNQMnAycc4r4W/ao/5Jpaf9hrTv/SmOvWPhX4q8UfBvw/feCPF/wAOvFugaZ4o8QavF4f1DVtasdSjtYXtLi6gtpGS9mmyIrWbnBUH+LmvOP2jPD+peJfANtaaXZTX1yuq2MxihXcwRJ0Zm+gAJoEYPxSs7j4V+LtP+J2lx50xkSz8S2yD79uSAlxx/FGTk/7JNQ+LbyHUP2o/hbdW0izW82ganJHIhyGUtbkEfhXtd1p8GqaZLZXkKz208RilikGVZSMEEV8yeB/hp4x8H/tFeHNPn0+a78E6BY38Wmax12xTtGyW7+mzyyAfQj8QR9FeN/8AkTdc/wCvKb/0A1w37K//ACbp8Pf+wRD/ACrvvF1vLeeFdXggjaWaS0lREUZLMUIAFch+zroWoeGPgb4K0nVbSSx1Kz02OG4tphho3HBBoEef+LPG0fgn9p6SeXSdU1VZvDqpt0u285kImz8wzxn+lXNTsdY+PXjvwldTeHr/AMP+F/DN+NVFxqarHLd3ARkRVTJIUbiSTjtXUW/h/UV/aNutYNlMNLbQVtxd7f3ZkEudufXFeo0DCiiigQUUUUAFFFFABRRRQAVX1TTLHXNI1LStTtEv9M1KznsLu2kd0EsM0TRSLuRlYZVzyCCKsUUAcxq3w30jXrI2ep6h4v1G0Mkcpt7vx1r0se+N1kjba18RlXVWB7FQRyKNT+G+ka1FBFqOoeL7+OCeO6iS68da9II5o2DxyKGvjh1YBlYcggEc109FAzGtPB+mW+r6fqc9x4g1e6055ZbNda8V6vqMMEskEtu0qxXF28e/y55VDFTjefWtmiigAooooEFFFFABRRRQAUUUUAFFFFABRRRQAUU7bRtoAbXW/Cn/AJH7S/8Atr/6KeuU211nwpX/AIr7S/8Atr/6KegZjftAfHP4i+D/ABdqWifYl+GPgaGBXh+I9zYNrK3bFUJjRE/caeQxZfOvSY++wivD/hZ8ffjB4X1bxqug+Htb8c6bc6jZzPrGrau3ioWXmafFKsccemrgpMXaQPCqQoBsxkjH0X+1T+03oHwp8J6zomk+OdJ0P4hq9gIrWZFuJraGe6iSSYwnhtsBlkwey56V8+aT8XvCvwR1XT9R8I/HvwfrNtqfiaw/4SHSdJ8KWFgLmCWZEubiWSABgyRFnL+2T1oKPpz4S/Ebxr8SfhX4wvfGvhV/DF1atcW1ozWlxZi+h+zK5lFvcASx7Xd4/m4by9w4NfL/AO0vrWqaH8Nlm0fU7nSLybUrO2+1WjbZFWSdEbB+hNfadj8RPDPxQ+Gms634S1yz8QaSbe6t/tljJvQSIhDIfQjjg+tfEX7VIx8NLT/sNad/6Ux0CHyfBbxPHCs2nfFXxNFdAZX7WYp4ifRlK9Km+FfxG1+bxbqvgTxtFbr4l0+JbmC+tFKw39sxwJFU52sCMFcmvV4V/cp/uj+VeH+I4WvP2vfCT2fzfYvDl4L1lx8oeWPyw312sR9KBG54N8Rane/Hzx7pE99NLplnZWMlvas2UiZw+4qO2cCu1+IN5Pp/gXX7q2laC4hsZpI5YzhlYISCD614cul+MdS/aV8fjwpren6MU0+w8431ibnfxJjGHXGK2PiF4Z+LsfgXX3uPGugS262UpkjXRGUsu05APnccUAdN8M/iIum/s3+GfGXinUGlK6DBf315Mcs7GIMzH3J/nWPoOkeP/i5Yxa5qPiK78DaTdDzLTS9LRPtHlH7rSyMDhiMHA6ZrzrxI00f7C3gRo/8Aj3Floxu89Ps+6LzM+23NfVOm+U+nWrQEGAxKU29NuBjH4UAcf4B8EeIfB+o3g1HxjfeKNMmjHkx6lGnnQOD1DqBuBHr6V5F8O9F8TfFTxV8S2n+IHiLSItI8RS6fZ29jOojjjEUbgYKnoXNfS22vlH4Q+NfE3hnxp8XbfQ/A174ohk8VTO1zb3kMKxv5EI2EOQegByPWgD0f4c+J/FHhf4qX/wAPfFGqDxDEbBdS03VmiEczR7trxygcEg45GOtey15R8N/A3iPUPHmoeP8AxjBb6dqtxaLYWWlW0vmraQBtx3PgAux644GMV6ztoAbRTttFAhaKKKACs/xP461D4Y+DfFXi/SUt5NU0LQtS1G1S6QvEZYrSV0DqCCVyoyARWhUlvcS2snmQyvDJgrvjYqcEEEZHqCR+NAzzDxR8ZJfhXfeLviBoH7Tnwc8UeIfEM+kWl1pdvpsWPLjmW2EkYXV2KhI53lfIIIj6qMkSap8arj4S32r65oH7T/wc8SXnjLxTp8mpwR6bERaCSO1sXuVC6uSIooYEkYH+6xLKOnqP9q3v/P5cf9/W/wAaP7Vvf+fy4/7+t/jQO55/4Q+Ip8A+I7Xw/oPxz+G3xStfHXiLVrvVdJ8O2SJe2zTadeXTzoyajPtiWS2iTDRn/WgFs4zj/tEeEdb8afD0WPh+zW/1KK/tbpIHlWMMI5lcjceBwtesf2te4YfbLjDKVP71uQQQR16EEj8aq0CPIm8XfFzUI0trPwHpmlOw2m61DVldE9wsakt9OPrW78MPhdJ4NutT1vWdQOt+K9WZWvdQZdqqq52xRr/DGuTgV6BRQB5n4T8F6tpfxu8a+Ibm3CaVqdpZxW0wdSXaMPuGM5H3h1rsPHWmXGteDNbsLRPMurmzliiQkDLMpAGT71uUUCPNfh78MgP2f/D/AIF8VWcchj0SHTb+33B13CMKwB6HkcGuS8MaP8WfhDbx6DZWOn+PvDVsCljcz3xtr6GIfcjk3gq+Bxu3A8dK93ooGcX4E1Lxzqt9dT+KdI03Q7HYBb2trdNcTFs8l22hRx2GfrXO/A/wHrPgvWviPc6tbrBFrXiKTUbMrIG3wmKNATjocoeDXq1FABRRRQIKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD//2Q==
"@
$way2Img =@"
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
"@
$way3Img =@"
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
"@

        $frmVCFLCMain = New-Object system.Windows.Forms.Form
        $frmVCFLCMain.Text = "VCF Lab Constructor beta 4.1"
        $frmVCFLCMain.TopMost = $true
        $frmVCFLCMain.Width = 850
        $frmVCFLCMain.Height = 450
        $frmVCFLCMain.BackColor = [System.Drawing.Color]::DarkGray
        $frmVCFLCMain.ControlBox = $false
        $mainMenu=New-Object System.Windows.Forms.MenuStrip
        $frmVCFLCMain.Controls.Add($mainMenu)

        (addMenuItem -ParentItem ([ref]$mainMenu) -ItemName 'mnuFile' -ItemText 'File' -ScriptBlock $null) | %{ 
        $null=addMenuItem -ParentItem ([ref]$_) -ItemName 'mnuFileOpen' -ItemText 'Load' -ScriptBlock $sbLoadSettings; 
        $null=addMenuItem -ParentItem ([ref]$_) -ItemName 'mnuFileSave' -ItemText 'Save' -ScriptBlock $sbSaveSettings; 
        $null=addMenuItem -ParentItem ([ref]$_) -ItemName 'mnuFileExit' -ItemText 'Exit' -ScriptBlock $sbExit;} | Out-Null; 

        $pnlWaysPanel = New-Object System.Windows.Forms.Panel
        $pnlWaysPanel.Width = 425
        $pnlWaysPanel.Height = 450
        $pnlWaysPanel.BringToFront()
        $frmVCFLCMain.Controls.Add($pnlWaysPanel)

        $btnWay1 = New-Object System.Windows.Forms.Button
        $btnWay1.Name = "btnWay1"
        $btnWay1.Height = 130
        $btnWay1.Width = 425
        $btnWay1.Text = "Automated"
        $btnWay1.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
        $btnWay1.ForeColor = [System.Drawing.Color]::"White"
        $btnWay1.Font = New-Object System.Drawing.Font("Console",20,[System.Drawing.FontStyle]::Bold)
        $btnWay1.location = new-object system.drawing.point(0,25)
        $btnWay1.Image = $(convert64Img $way2Img)
        $btnWay1.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $btnWay1.Add_Click({setFormControls "internalsvcs"})
        $btnWay1.Add_MouseHover($ShowTips)
        $pnlWaysPanel.Controls.Add($btnWay1)

        $btnWay2 = New-Object System.Windows.Forms.Button
        $btnWay2.Name = "btnWay2"
        $btnWay2.Height = 130
        $btnWay2.Width = 425
        $btnWay2.Text = "Manual"
        $btnWay2.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
        $btnWay2.ForeColor = [System.Drawing.Color]::"White"
        $btnWay2.Font = New-Object System.Drawing.Font("Console",20,[System.Drawing.FontStyle]::Bold)
        $btnWay2.Image = $(convert64Img $way1Img)
        $btnWay2.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $btnWay2.location = new-object system.drawing.point(0,155)
        $btnWay2.Add_Click({setFormControls "externalsvcs"})
        $btnWay2.Add_MouseHover($ShowTips)
        $pnlWaysPanel.Controls.Add($btnWay2)

        $btnWay3 = New-Object System.Windows.Forms.Button
        $btnWay3.Name = "btnWay3"
        $btnWay3.Height = 130
        $btnWay3.Width = 425
        $btnWay3.Text = "Expansion Pack!"
        $btnWay3.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
        $btnWay3.ForeColor = [System.Drawing.Color]::"White"
        $btnWay3.Font = New-Object System.Drawing.Font("Console",20,[System.Drawing.FontStyle]::Bold)
        $btnWay3.Image = $(convert64Img $way3Img)
        $btnWay3.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $btnWay3.location = new-object system.drawing.point(0,285)
        $btnWay3.Add_Click({setFormControls "expansion"})
        $btnWay3.Add_MouseHover($ShowTips)
        $pnlWaysPanel.Controls.Add($btnWay3)

        $txtMgmtNet = New-Object system.windows.Forms.TextBox
        $txtMgmtNet.Name = "txtMgmtNet"
        $txtMgmtNet.Width = 100
        $txtMgmtNet.Height = 20
        $txtMgmtNet.location = new-object system.drawing.point(200,77)
        $txtMgmtNet.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtMgmtNet.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtMgmtNet)
        
        $txtMgmtNetVLAN = New-Object System.Windows.Forms.TextBox
        $txtMgmtNetVLAN.Name = "txtMgmtNetVLAN"
        $txtMgmtNetVLAN.Width = 50
        $txtMgmtNetVLAN.Height = 20
        $txtMgmtNetVLAN.location = new-object system.drawing.point(50,77)
        $txtMgmtNetVLAN.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtMgmtNetVLAN.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtMgmtNetVLAN)

        $txtLabGateway = New-Object System.Windows.Forms.TextBox
        $txtLabGateway.Name = "txtLabGateway"
        $txtLabGateway.Width = 100
        $txtLabGateway.Height = 20
        $txtLabGateway.location = new-object system.drawing.point(50,102)
        $txtLabGateway.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtLabGateway.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtLabGateway)

        $txtMgmtGateway = New-Object system.windows.Forms.TextBox
        $txtMgmtGateway.Name = "txtMgmtGateway"
        $txtMgmtGateway.Width = 100
        $txtMgmtGateway.Height = 20
        $txtMgmtGateway.location = new-object system.drawing.point(200,102)
        $txtMgmtGateway.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtMgmtGateway.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtMgmtGateway)

        $txtCBIP = New-Object system.windows.Forms.TextBox
        $txtCBIP.Name = "txtCBIP"
        $txtCBIP.Width = 100
        $txtCBIP.Height = 20
        $txtCBIP.location = new-object system.drawing.point(200,127)
        $txtCBIP.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($txtCBIP)
        $txtCBIP.Add_TextChanged({

                    if($chkInternalSvcs.Checked) {

                        $txtNTP.Text = $txtCBIP.Text
                        $txtDNS.Text = $txtCBIP.Text

                    }
        })
        $txtCBIP.Add_MouseHover($ShowTips)

        $txtCBLoc = New-Object system.windows.Forms.TextBox
        $txtCBLoc.Name = "txtCBLoc"
        $txtCBLoc.Width = 250
        $txtCBLoc.Height = 20
        $txtCBLoc.Add_Click({

                    $CBFullName = Get-FileName "$scriptDir" "OVA (*.ova)| *.ova" "load"
                    $txtCBLoc.Text = $CBFullName
                    })
        $txtCBLoc.Add_MouseHover($ShowTips)
        $txtCBLoc.location = new-object system.drawing.point(50,152)
        $txtCBLoc.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($txtCBLoc)

        $txtNestedJSON = New-Object system.windows.Forms.TextBox
        $txtNestedJSON.Name = "txtNestedJSON"
        $txtNestedJSON.Width = 250
        $txtNestedJSON.Height = 20
        $txtNestedJSON.Add_Click({

                    $jsonFullName = Get-FileName "$scriptDir" "JSON (*.json)| *.json" "load"
                    $txtNestedJSON.Text = $jsonFullName   
                    })
        $txtNestedJSON.Add_MouseHover($ShowTips)
        $txtNestedJSON.location = new-object system.drawing.point(50,177)
        $txtNestedJSON.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($txtNestedJSON)
        
        $txtvSphereLoc = New-Object system.windows.Forms.TextBox
        $txtvSphereLoc.Name = "txtvSphereLoc"
        $txtvSphereLoc.Width = 150
        $txtvSphereLoc.Height = 20
        $txtvSphereLoc.Add_Click({

            $vSphereISOLoc = Get-FileName "$scriptDir" "ISO (*.iso)| *.iso" "load"
            $txtvSphereLoc.Text = $vSphereISOLoc 
                        })
        $txtvSphereLoc.Add_MouseHover($ShowTips)
        $txtvSphereLoc.location = new-object system.drawing.point(150,202)
        $txtvSphereLoc.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($txtvSphereLoc)

        $txtVMPrefix = New-Object system.windows.Forms.TextBox
        $txtVMPrefix.Name = "txtVMPrefix"
        $txtVMPrefix.Width = 100
        $txtVMPrefix.Height = 20
        $txtVMPrefix.MaxLength = 8
        $txtVMPrefix.location = new-object system.drawing.point(200,227)
        $txtVMPrefix.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtVMPrefix.Add_TextChanged({

            if ($txtVMPrefix){
    
                $lblVMPrefixEx.Text = ($txtVMPrefix.Text + "-esxi-01a")

                } else {

                 $lblVMPrefixEx.Text = ""
                
                }
        
        })
        $txtVMPrefix.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtVMPrefix)

        $chkUseCBIso = New-Object system.windows.Forms.CheckBox
        $chkUseCBIso.Name = "chkUseCBIso"
        $chkUseCBIso.text = "Use CB ESXi?"
        $chkUseCBIso.Width = 100
        $chkUseCBIso.Height = 20
        $chkUseCBIso.location = new-object system.drawing.point(50,202)
        $frmVCFLCMain.controls.Add($chkUseCBIso)
        $chkUseCBIso.Add_CheckStateChanged({

            if($chkUseCBIso.Checked -eq $true) {
                $txtvSphereLoc.Text = ""
                $txtvSphereLoc.Enabled = $false
                $lblvSphereLoc.Enabled = $false
            } else {
                $txtvSphereLoc.Enabled = $true
                $lblvSphereLoc.Enabled = $true
            }
        })

        $txtMasterPass = New-Object system.windows.Forms.TextBox
        $txtMasterPass.Name = "txtMasterPass"
        $txtMasterPass.Width = 250
        $txtMasterPass.Height = 20
        $txtMasterPass.location = new-object system.drawing.point(50,252)
        $txtMasterPass.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtMasterPass.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtMasterPass)

        $txtNTP = New-Object system.windows.Forms.TextBox
        $txtNTP.Name = "txtNTP"
        $txtNTP.Width = 100
        $txtNTP.Height = 20
        $txtNTP.location = new-object system.drawing.point(50,276)
        $txtNTP.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtNTP.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtNTP)

        $txtDNS = New-Object system.windows.Forms.TextBox
        $txtDNS.Name = "txtDNS"
        $txtDNS.Width = 100
        $txtDNS.Height = 20
        $txtDNS.location = new-object system.drawing.point(200,276)
        $txtDNS.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtDNS.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtDNS)

        $txtDomainName = New-Object system.windows.Forms.TextBox
        $txtDomainName.Name = "txtDomainName"
        $txtDomainName.Width = 250
        $txtDomainName.Height = 20
        $txtDomainName.location = new-object system.drawing.point(50,300)
        $txtDomainName.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtDomainName.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtDomainName)
        
        $txtBringupFile = New-Object system.windows.Forms.TextBox
        $txtBringupFile.Name = "txtBringupFile"
        $txtBringupFile.Width = 250
        $txtBringupFile.Height = 20
        $txtBringupFile.location = new-object system.drawing.point(50,52)
        $txtBringupFile.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10" 
        $frmVCFLCMain.controls.Add($txtBringupFile)
        $txtBringupFile.Add_Click({

                    $jsonFullName = Get-FileName "$scriptDir" "JSON (*.json)| *.json" "load"
                    if($jsonFullName -ne "") {
                        $txtBringupFile.Text = $jsonFullName 
                        $global:bringUpOptions = Get-Content -Raw $jsonFullName  | ConvertFrom-Json  
                        parseBringUpFile 
                    } else {
                        $txtDNS.enabled = $true
                        $txtNTP.enabled = $true
                        $txtMasterPass.Enabled = $true
                    }
                    
        })
        $txtBringupFile.Add_MouseHover($ShowTips)
        <#
        $chkEC = New-Object system.windows.Forms.CheckBox
        $chkEC.Name = "chkEC"
        $chkEC.Text = "Prep for Edge Cluster?"
        $chkEC.AutoSize = $true
        $chkEC.Width = 105
        $chkEC.Height = 20
        $chkEC.location = new-object system.drawing.point(305,325)
        $chkEC.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $chkEC.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($chkEC)
        #>
        $chkHostOnly = New-Object system.windows.Forms.CheckBox
        $chkHostOnly.Visible = $false
        $chkHostOnly.Name = "chkHostOnly"
        $chkHostOnly.Text = "Hosts Only?"
        $chkHostOnly.AutoSize = $true
        $chkHostOnly.Width = 105
        $chkHostOnly.Height = 20
        $chkHostOnly.location = new-object system.drawing.point(305,345)
        $chkHostOnly.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $chkHostOnly.Add_CheckStateChanged({

            if($chkHostOnly.Checked) {
            
                setFormControls "expansion"

            } else {
                $txtDNS.Enabled = $true
                $txtNTP.Enabled = $true
                $chkInternalSvcs.Enabled = $true
                $chkSb.Enabled = $true
                $txtCBLoc.Enabled = $true
                $txtCBIP.Enabled = $true
                $txtDomainName.Enabled = $true
                $txtMgmtNet.Enabled = $true
                $txtMgmtGateway.Enabled = $true
            }

        })
        $chkHostOnly.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($chkHostOnly)

        $chkSb = New-Object system.windows.Forms.CheckBox
        $chkSb.Name = "chkSb"
        $chkSb.Text = "Do Bringup?"
        $chkSb.AutoSize = $true
        $chkSb.Width = 95
        $chkSb.Height = 20
        $chkSb.location = new-object system.drawing.point(305,365)
        $chkSb.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"

        $chkSb.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($chkSb)

        $chkInternalSvcs = New-Object system.windows.Forms.CheckBox
        $chkInternalSvcs.Visible = $false
        $chkInternalSvcs.Name = "chkInternalSvcs"
        $chkInternalSvcs.Text = "Internal Svcs?"
        $chkInternalSvcs.AutoSize = $true
        $chkInternalSvcs.Width = 95
        $chkInternalSvcs.Height = 20
        $chkInternalSvcs.Enabled = $false
        $chkInternalSvcs.location = new-object system.drawing.point(305,385)
        $chkInternalSvcs.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $chkInternalSvcs.Add_CheckStateChanged({

            if ($chkInternalSvcs.Checked) {
                if (Test-IP $txtCBIP.Text) {
                    $txtDNS.Enabled = $false
                    $txtNTP.Enabled = $false
                    $txtDNS.text = $txtCBIP.Text
                    $txtNTP.text = $txtCBIP.Text
                    

                 }
            } else {

            $txtDNS.Enabled = $true
            $txtNTP.Enabled = $true

            }
         }
        )
        $chkInternalSvcs.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($chkInternalSvcs)

        $lblConflictWarning = New-Object System.Windows.Forms.Label
        $lblConflictWarning.Height = 20
        $lblConflictWarning.AutoSize = $true
        $lblConflictWarning.location = new-object system.drawing.point(455,387)
        $lblConflictWarning.text = "*Ensure vcf-ems JSON DNS and NTP IPs match the VLC settings!*"
        $lblConflictWarning.ForeColor = [System.Drawing.Color]::"Red"
        $lblConflictWarning.BackColor = [System.Drawing.Color]::"Yellow"
        $lblConflictWarning.Visible = $false
        $frmVCFLCMain.controls.Add($lblConflictWarning)

        $txtHostIP = New-Object system.windows.Forms.TextBox
        $txtHostIP.Name = "txtHostIP"
        $txtHostIP.Width = 250
        $txtHostIP.Height = 20
        $txtHostIP.location = new-object system.drawing.point(540,50)
        $txtHostIP.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtHostIP.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtHostIP)

        $txtUsername = New-Object system.windows.Forms.TextBox
        $txtUsername.Name = "txtUsername"
        $txtUsername.Width = 250
        $txtUsername.Height = 20
        $txtUsername.location = new-object system.drawing.point(540,80)
        $txtUsername.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtUsername.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtUsername)

        $txtPassword = New-Object system.windows.Forms.MaskedTextBox
        $txtPassword.Name = "txtPassword"
        $txtPassword.PasswordChar = '*'
        $txtPassword.Width = 250
        $txtPassword.Height = 20
        $txtPassword.location = new-object system.drawing.point(540,110)
        $txtPassword.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $txtPassword.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($txtPassword)

        $listCluster = New-Object System.Windows.Forms.ListBox
        $listCluster.Name = "listCluster"
        $listCluster.Width = 250
        $listCluster.Height = 40
        $listCluster.location = new-object system.drawing.point(540,170)
        $listCluster.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $listCluster.Enabled = $false
        $listCluster.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($listCluster)

        $listNetName = New-Object system.windows.Forms.ListBox
        $listNetName.Name = "listNetName"
        $listNetName.Width = 250
        $listNetName.Height = 40
        $listNetName.location = new-object system.drawing.point(540,210)
        $listNetName.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $listNetName.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($listNetName)

        $listDatastore = New-Object system.windows.Forms.ListBox
        $listDatastore.Name = "listDatastore"
        $listDatastore.Width = 250
        $listDatastore.Height = 40
        $listDatastore.location = new-object system.drawing.point(540,250)
        $listDatastore.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $listDatastore.Add_MouseHover($ShowTips)
        $frmVCFLCMain.controls.Add($listDatastore)

        $listResourcePool = New-Object system.windows.Forms.ListBox
        $listResourcePool.Name = "listResourcePool"
        $listResourcePool.Width = 250
        $listResourcePool.Height = 40
        $listResourcePool.location = new-object system.drawing.point(540,290)
        $listResourcePool.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $listResourcePool.Add_MouseHover($ShowTips)
        #$frmVCFLCMain.controls.Add($listResourcePool)

        $lblDomainName = New-Object system.windows.Forms.Label
        $lblDomainName.Text = "Full Domain"
        $lblDomainName.AutoSize = $true
        $lblDomainName.Width = 25
        $lblDomainName.Height = 10
        $lblDomainName.location = new-object system.drawing.point(305,302)
        $lblDomainName.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblDomainName)

        $lblMgmtNet = New-Object system.windows.Forms.Label
        $lblMgmtNet.Text = "Mgmt Net CIDR"
        $lblMgmtNet.AutoSize = $true
        $lblMgmtNet.Width = 25
        $lblMgmtNet.Height = 10
        $lblMgmtNet.location = new-object system.drawing.point(305,80)
        $lblMgmtNet.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblMgmtNet)

        $lblMgmtNetVLAN = New-Object system.windows.Forms.Label
        $lblMgmtNetVLAN.Text = "Main VLAN"
        $lblMgmtNetVLAN.AutoSize = $true
        $lblMgmtNetVLAN.Width = 25
        $lblMgmtNetVLAN.Height = 10
        $lblMgmtNetVLAN.location = new-object system.drawing.point(105,80)
        $lblMgmtNetVLAN.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblMgmtNetVLAN)

        $lblLabGateway = New-Object system.windows.Forms.Label
        $lblLabGateway.Text = "Ext GW"
        $lblLabGateway.AutoSize = $true
        $lblLabGateway.Width = 25
        $lblLabGateway.Height = 10
        $lblLabGateway.location = new-object system.drawing.point(155,105)
        $lblLabGateway.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblLabGateway)

        $lblMgmtGateway = New-Object system.windows.Forms.Label
        $lblMgmtGateway.Text = "Mgmt GW"
        $lblMgmtGateway.AutoSize = $true
        $lblMgmtGateway.Width = 25
        $lblMgmtGateway.Height = 10
        $lblMgmtGateway.location = new-object system.drawing.point(305,105)
        $lblMgmtGateway.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblMgmtGateway)

        $lblMasterPass = New-Object system.windows.Forms.Label
        $lblMasterPass.Text = "Host/CB Password"
        $lblMasterPass.AutoSize = $true
        $lblMasterPass.Width = 25
        $lblMasterPass.Height = 10
        $lblMasterPass.location = new-object system.drawing.point(305,255)
        $lblMasterPass.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblMasterPass)

        $lblCBLoc = New-Object system.windows.Forms.Label
        $lblCBLoc.Text = "*CB OVA Location"
        $lblCBLoc.AutoSize = $true
        $lblCBLoc.Width = 25
        $lblCBLoc.Height = 10
        $lblCBLoc.location = new-object system.drawing.point(305,155)
        $lblCBLoc.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblCBLoc)

        $lblNestedJSON = New-Object system.windows.Forms.Label
        $lblNestedJSON.Text = "Addtl Hosts JSON"
        $lblNestedJSON.AutoSize = $true
        $lblNestedJSON.Width = 25
        $lblNestedJSON.Height = 10
        $lblNestedJSON.location = new-object system.drawing.point(305,180)
        $lblNestedJSON.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblNestedJSON)

        $lblvSphereLoc = New-Object system.windows.Forms.Label
        $lblvSphereLoc.Text = "ESXi ISO Location"
        $lblvSphereLoc.AutoSize = $true
        $lblvSphereLoc.Width = 25
        $lblvSphereLoc.Height = 10
        $lblvSphereLoc.location = new-object system.drawing.point(305,205)
        $lblvSphereLoc.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblvSphereLoc)

        $lblVMPrefix = New-Object system.windows.Forms.Label
        $lblVMPrefix.Text = "Prefix for VMs"
        $lblVMPrefix.AutoSize = $true
        $lblVMPrefix.Width = 25
        $lblVMPrefix.Height = 10
        $lblVMPrefix.location = new-object system.drawing.point(305,230)
        $lblVMPrefix.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblVMPrefix)

        $lblVMPrefixEx = New-Object system.windows.Forms.Label
        $lblVMPrefixEx.Text = ""
        $lblVMPrefixEx.AutoSize = $true
        $lblVMPrefixEx.Width = 25
        $lblVMPrefixEx.Height = 10
        $lblVMPrefixEx.location = new-object system.drawing.point(50,230)
        $lblVMPrefixEx.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblVMPrefixEx)

        $lblBringUpFile = New-Object system.windows.Forms.Label
        $lblBringUpFile.Text = "VCF EMS JSON"
        $lblBringUpFile.AutoSize = $true
        $lblBringUpFile.Width = 25
        $lblBringUpFile.Height = 10
        $lblBringUpFile.Visible = $true
        $lblBringUpFile.location = new-object system.drawing.point(305,55)
        $lblBringUpFile.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblBringUpFile)

        $lblNTP = New-Object system.windows.Forms.Label
        $lblNTP.Text = "NTP IP"
        $lblNTP.AutoSize = $true
        $lblNTP.Width = 25
        $lblNTP.Height = 10
        $lblNTP.location = new-object system.drawing.point(152,279)
        $lblNTP.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblNTP)

        $lblDNS = New-Object system.windows.Forms.Label
        $lblDNS.Text = "DNS IP"
        $lblDNS.AutoSize = $true
        $lblDNS.Width = 25
        $lblDNS.Height = 10
        $lblDNS.location = new-object system.drawing.point(305,279)
        $lblDNS.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblDNS)

        $lblCBIP = New-Object system.windows.Forms.Label
        $lblCBIP.Text = "CB IP"
        $lblCBIP.AutoSize = $true
        $lblCBIP.Width = 25
        $lblCBIP.Height = 10
        $lblCBIP.location = new-object system.drawing.point(305,130)
        $lblCBIP.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblCBIP)

        $lblHost = New-Object system.windows.Forms.Label
        $lblHost.Text = "Host/VC IP/FQDN*"
        $lblHost.AutoSize = $false
        $lblHost.Width = 130
        $lblHost.Height = 15
        $lblHost.location = new-object system.drawing.point(410,55)
        $lblHost.TextAlign = "MiddleRight"
        $lblHost.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblHost)

        $lblHostUser = New-Object system.windows.Forms.Label
        $lblHostUser.Text = "Username*"
        $lblHostUser.AutoSize = $false
        $lblHostUser.Width = 100
        $lblHostUser.Height = 10
        $lblHostUser.location = new-object system.drawing.point(425,85)
        $lblHostUser.TextAlign = "MiddleRight"
        $lblHostUser.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblHostUser)

        $lblPass = New-Object system.windows.Forms.Label
        $lblPass.Text = "Password*"
        $lblPass.AutoSize = $false
        $lblPass.Width = 100
        $lblPass.Height = 10
        $lblPass.location = new-object system.drawing.point(425,115)
        $lblPass.TextAlign = "MiddleRight"
        $lblPass.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblPass)

        $btnConnect = New-Object System.Windows.Forms.Button
        $btnConnect.Text = "Connect"
        $btnConnect.Width = 100
        $btnConnect.Height = 30
        $btnConnect.Add_Click({
            Get-VIInfo $txtHostIP.Text $txtUsername.Text $txtPassword.Text
                })

        $btnConnect.location = New-Object System.Drawing.Point (615,136)
        $frmVCFLCMain.Controls.Add($btnConnect)

        $btnBack = New-Object System.Windows.Forms.Button
        $btnBack.Text = "<-Back"
        $btnBack.Width = 50
        $btnBack.Height = 40
        $btnBack.Add_Click({

            If ($btnSubmit.Text -like "Construct!") {
                UnlockFormFields
                $btnSubmit.Text = "Validate"
                $btnSubmit.ForeColor=[System.Drawing.Color]::"Black"
                $btnSubmit.BackColor=[System.Drawing.Color]::"Yellow"
            } else {
                ClearFormFields
                $pnlWaysPanel.Visible = $true
                $btnExpert.Visible = $true
            }
        })
        $btnBack.location = New-Object System.Drawing.Point (15,370)
        $frmVCFLCMain.Controls.Add($btnBack)

        $btnClear = New-Object System.Windows.Forms.Button
        $btnClear.Text = "Clear"
        $btnClear.Width = 100
        $btnClear.Height = 40
        $btnClear.Add_Click({
            ClearFormFields
                })
        $btnClear.location = New-Object System.Drawing.Point (75,370)
        $frmVCFLCMain.Controls.Add($btnClear)

        $btnSubmit = New-Object System.Windows.Forms.Button
        $btnSubmit.Text = "Validate"
        $btnSubmit.ForeColor = [System.Drawing.Color]::"Black"
        $btnSubmit.BackColor = [System.Drawing.Color]::"Yellow"
        $btnSubmit.Width = 100
        $btnSubmit.Height = 40
        $btnSubmit.Add_Click({

            # Validation

                if ($btnSubmit.Text -eq "Construct!")
                    {
					    # Submit

                        if ($txtVMPrefix.TextLength -gt 0) {
                                $global:vmPrefix = $txtVMPrefix.Text + "-"
                                $global:CBName = $global:vmPrefix + "CB-01a"
						    } else {
							    $global:vmPrefix = ""
                                $global:CBName = "CB-01a"
						    }            
                    
	                    $global:CBISOLoc = $txtCBLoc.Text
                        $global:vsphereISOLoc = $txtvSphereLoc.Text
                        $global:jsonLoc = $txtNestedJSON.Text

<#                        If ($chkEC.Checked) {
	                            $global:allFlashBuild = $true
                            } else {
                                $global:allFlashBuild = $false
						    }
#>                    
                        $cidrMgmt=$txtMgmtNet.Text

                        $global:VCFEMSFile = $txtBringupFile.Text

	                    $global:userOptions = @{	
	                    "esxhost"=$txtHostIP.Text
	                    "username"=$txtUsername.Text
	                    "password"=$txtPassword.Text
	                    "netName"=$listNetName.SelectedItem
                        "cluster"=$listCluster.SelectedItem
                        "Typeguestdisk"="Thin"
	                    "ds"=$listDatastore.SelectedItem
                        "masterPassword"=$txtMasterPass.Text
                        "guestOS"="vmkernel65guest"
                        "cbIPAddress"=$txtCBIP.Text 
                        "dnsServer"=$txtDNS.Text
                        "ntpServer"=$txtNTP.Text
                        "mgmtNetGateway"=$txtMgmtGateway.Text
                        "mgmtNetSubnet"=$txtMgmtNet.Text
                        "mgmtNetCidr"=$cidrMgmt.Substring(($cidrMgmt.IndexOf("/")+1),($cidrMgmt.Length - ($cidrMgmt.IndexOf("/") +1)))
                        "vcfDomainName"=$txtDomainName.Text
                        "nestedVMPrefix"=$global:vmPrefix
                        "mgmtNetVlan"=$txtMgmtNetVLAN.Text
                        "labGateway"=$txtLabGateway.Text

                        }

                        If ($chkHostOnly.Checked) {

                        } elseif ($chkSb.Checked) {
                            $global:bringupAfterBuild = $true
                        } elseif ($chkInternalSvcs.checked) {
                            $global:imageAfterBuild = $true
                      
                        } else {
                    	    $global:imageAfterBuild = $false

                        }

                
                        logger "----------------------Form Inputs------------------3.0--"
                        logger "esxhost:"
                        logger $txtHostIP.Text
	                    logger "username:"
                        logger $txtUsername.Text
	                    logger "password:"
                        logger $txtPassword.Text
	                    logger "netName:"
                        logger $listNetName.SelectedItem
                        logger "cluster:"
                        logger $listCluster.SelectedItem
                        logger "datastore:"
                        logger $listDatastore.SelectedItem
                        logger "Domain Name:"
                        logger $txtDomainName.Text
                        logger "Mgmt CIDR:"
                        logger $txtMgmtNet.Text
                        logger "Mgmt Gateway:" 
                        logger $txtMgmtGateway.Text
                        logger "vmPrefix:"
                        logger $global:vmprefix.Text
                        logger "CB OVA Loc:"
                        logger $txtCBLoc.Text
                        logger "vsphereISOLoc: $($chkUseCBIso.Checked)" 
                        logger $txtvSphereLoc.Text
                        logger "jsonLoc:"
                        logger $txtNestedJSON.Text
                        logger "Master Pass:"
                        logger $txtMasterPass.Text
                        logger "NTP IP:"
                        logger $txtNTP.Text
                        logger "DNS IP:"
                        logger $txtDNS.Text
                        logger "Config Internal Svcs:"
                        logger $chkInternalSvcs.Checked
                        logger "bringupAfterBuild:"
                        logger $chkSB.Checked
                        logger "bringup JSON:"
                        logger $global:VCFEMSFile
#                        logger "allFlashBuild" 
#                        logger $chkEC.Checked
                        logger "--------------------END-Form Inputs--------------------"

					    $frmVCFLCMain.Dispose()
                   
				    } else {

                            ValidateFormValues
                            Write-Host "Form is valid: $global:validationSuccess"
                        	if ($global:validationSuccess -eq $true)
				                {
                                    LockFormFields
                                    $btnSubmit.Text = "Construct!"
                                    $btnSubmit.BackColor = [System.Drawing.Color]::"DarkGreen"
                                    $btnSubmit.ForeColor = [System.Drawing.Color]::"White"
                                    logger "Validation complete, all checks passed!"
                                } Else {
                                    logger "Please Correct the Errors and/or missing values and re-validate"
                                }
				    }			
        })

        $btnSubmit.location = New-Object System.Drawing.Point (175,370)
        $frmVCFLCMain.Controls.Add($btnSubmit)


        $lblCluster = New-Object system.windows.Forms.Label
        $lblCluster.Text = "Cluster*"
        $lblCluster.AutoSize = $false
        $lblCluster.Width = 100
        $lblCluster.Height = 10
        $lblCluster.location = new-object system.drawing.point(425,180)
        $lblCluster.TextAlign = "MiddleRight"
        $lblCluster.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblCluster)

        $lblNetName = New-Object system.windows.Forms.Label
        $lblNetName.Text = "Network*"
        $lblNetName.AutoSize = $false
        $lblNetName.Width = 100
        $lblNetName.Height = 10
        $lblNetName.location = new-object system.drawing.point(425,220)
        $lblNetName.TextAlign = "MiddleRight"
        $lblNetName.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblNetName)

        $lblDatastore = New-Object system.windows.Forms.Label
        $lblDatastore.Text = "Datastore*"
        $lblDatastore.AutoSize = $false
        $lblDatastore.Width = 100
        $lblDatastore.Height = 10
        $lblDatastore.location = new-object system.drawing.point(425,260)
        $lblDatastore.TextAlign = "MiddleRight"
        $lblDatastore.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        $frmVCFLCMain.controls.Add($lblDatastore)

        $lblResourcePool = New-Object system.windows.Forms.Label
        $lblResourcePool.Text = "Resource Pool"
        $lblResourcePool.AutoSize = $false
        $lblResourcePool.Width = 100
        $lblResourcePool.Height = 10
        $lblResourcePool.location = new-object system.drawing.point(425,300)
        $lblResourcePool.TextAlign = "MiddleRight"
        $lblResourcePool.Font = [System.Drawing.Font]::"Microsoft Sans Serif,10"
        #$frmVCFLCMain.controls.Add($lblResourcePool)

        $PictureBox30 = New-Object system.windows.Forms.PictureBox
        $PictureBox30.Width = 723
        $PictureBox30.Height = 40
        $PictureBox30.location = new-object system.drawing.point(460,345)
        $frmVCFLCMain.controls.Add($PictureBox30)

        $PictureBox30.Image = $(convert64Img $formLogo)

        $btnExpert = New-Object System.Windows.Forms.Button
        $btnExpert.Width = 100
        $btnExpert.Height = 30
        $btnExpert.Location = New-Object System.Drawing.Point(575,385)
        $btnExpert.Text = "Expert Mode"
        $btnExpert.Visible = $true
        $btnExpert.Add_Click({
        
            setFormControls "enableall"
        
        })
        $frmVCFLCMain.controls.Add($btnExpert)

        [void]$frmVCFLCMain.ShowDialog()

        $frmVCFLCMain.Dispose()

if ($Global:isExit) {
    
        exit
    
}

#endregion Main Form

#region Host Creation Scriptblock

# Host Creation Scripblock
$createHostCode = {

	param($vmToGen, $userOptions, $logpath)

    # Set props from UI	
	$esxhost=$userOptions.esxhost
	$username=$userOptions.username
	$password=$userOptions.password
    $masterPassword=$userOptions.masterPassword
	$netName=$userOptions.netName
    $hostCluster=$userOptions.cluster
    $vmPrefix=$userOptions.nestedVMPrefix
	
	$Typeguestdisk=$userOptions.Typeguestdisk
	$ds=$userOptions.ds
	$guestOS=$userOptions.guestOS # Apparently vmkernel6guest is for 6.5?!
	
    # Set props from JSON
    $VM_name="$vmPrefix$($vmToGen.name)"
	$numcpu=$vmToGen.cpus
	$GBram=$vmToGen.mem
	$GBguestdisks=$vmToGen.disks.split(',')
	$mgmtIP=$vmToGen.mgmtIP

    $logfile = "$logPath\$VM_Name-VLC-Log-_$(get-date -format `"yyyymmdd_hhmmss`").txt"

    Function logger($strMessage, [switch]$logOnly)
    {
	    $curDateTime = get-date -format "hh:mm:ss"
	    $entry = "$curDateTime :> $strMessage"
	    if (!$logOnly) {
		    write-host $entry
		    $entry | out-file -Filepath $logfile -append
	    } else {
		    $entry | out-file -Filepath $logfile -append
	    }
    }

	
    # Import PowerCLI Module

    Import-Module -Name VMware.VimAutomation.Core

	$WarningPreference = "SilentlyContinue"

    logger $vmToGen -logOnly
	
      try {
        Write-host "Connecting to vCenter/Host, please wait.." -ForegroundColor green
        #Connect to vCenter
        Connect-viserver $esxhost -user $username -password $password -ErrorAction Stop | Out-Null
        logger "Connected to vCenter"  -logOnly
      }
      catch [Exception]{
        $status = 1
        $exception = $_.Exception
        Write-Host "Could not connect to vCenter" -ForegroundColor Red
        $msg = "Could not connect to vCenter"
        logger "$msg $status $error[0]"
      }

	#Connect-viserver $esxhost -user $username -password $password

	# Create VM

        write-host "Creation of VM initiated"  -foreground green
        logger "Creation of VM initiated" -logOnly
    if ($hostCluster -eq "") {
	    New-VM -Name $VM_Name -numcpu $numcpu -corespersocket $numcpu -MemoryGB $GBram -DiskGB $GBguestdisks[0] -DiskStorageFormat $Typeguestdisk -Datastore $ds -NetworkName $netName| Out-Null
    } else {
        $hostCluster = Get-Cluster $hostCluster
        New-VM -Name $VM_Name -numcpu $numcpu -corespersocket $numcpu -MemoryGB $GBram -DiskGB $GBguestdisks[0] -DiskStorageFormat $Typeguestdisk -Datastore $ds -ResourcePool $hostCluster -NetworkName $netName -ErrorAction Stop | Out-Null
    }

	write-host "Removing NIC"  -foreground green
	logger "Removing NIC" -logOnly
    # Remove Default E1000E NIC
	$remNic=Get-NetworkAdapter -VM $VM_Name
	if ($remNic) {
	    Remove-NetworkAdapter -NetworkAdapter $remNic -Confirm:$false | Out-Null
    }
	write-host "Fixing SCSI Controller"  -foreground green
    logger "Fixing SCSI Controller" -logOnly
	# Change to Paravirtual (vSphere 7)
	$chgScsi=Get-SCSIController -VM $VM_Name
	Set-SCSIController $chgScsi -Type ParaVirtual -Confirm:$false | Out-Null

	write-host "Creating Disks"  -foreground green
	logger "Creating Disks" -logOnly
    # Add remainder of disks from JSON
	for ($i=1; $i -le ($GBguestdisks.Count-1); $i++) {
		New-HardDisk -CapacityGB $GBguestdisks[$i] -VM $VM_name -Datastore $ds -ThinProvisioned:$true -Confirm:$false | Out-Null
	}
	 
	write-host "Fiddling with NICs"  -foreground green
    logger "Fiddling with NICs" -logOnly
    # Install hot new VMXNET3s
	New-NetworkAdapter -VM $VM_Name -NetworkName $netName -startConnected:$true -Type VMXNET3
	New-NetworkAdapter -VM $VM_Name -NetworkName $netName -startConnected:$true -Type VMXNET3

	write-host "Setting Guest OS Type"  -foreground green
    logger "Setting Guest OS Type" -logOnly
	# Set Guest OS Type
	Set-VM -VM $VM_Name -GuestId $guestOS -Confirm:$false | Out-Null

	write-host "Enabling VHV for Nested"  -foreground green
    logger "Enabling VHV for Nested" -logOnly
	# Enable VHV
	$nestVM = Get-VM $VM_name
	$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
	$spec.NestedHVEnabled = $true
	$nestVM.ExtensionData.ReconfigVM($spec) | Out-Null
	
	write-host "Creation of host $VM_Name completed"  -foreground green
    logger "Creation of host $VM_Name completed" -logOnly
	
	write-host "Gathering MAC address"  -foreground green

    try {
        Start-VM -VM $VM_Name
        logger "Attempting to start VM" -logOnly
    }
        catch [Exception]{
        $status = 1
        $exception = $_.Exception
        Write-Host "Could not Start VM" -ForegroundColor Red
        $msg = "Could not Start VM"
        logger "$msg $status $($error[0])" -logOnly
        Write-Error "Could not Start VM" -ErrorAction Stop
    }

	sleep 5
	write-host "Stopping VM"  -foreground red
    logger "Stopping VM" -logOnly
	Stop-VM -VM $VM_Name -confirm:$false | out-null
	
        Do {
            $vmPower = Get-VM $VM_Name
            write-host "Waiting to STOP!"
            Sleep 5
         } until ( $vmPower.Powerstate -eq "Poweredoff" )

    sleep 5
	$hostNetAdapter = Get-NetworkAdapter -VM $VM_Name
	$hostMacAddress = "01-" + $hostNetAdapter[0].MacAddress -replace ":","-"
	write-host "MAC address is ${hostMacAddress}      "  -foreground green
    logger "MAC address is ${hostMacAddress}" -logOnly
	sleep 5
}
#endregion Host Creation

#region Host Startup Scriptblock
#Host Startup Scriptblock
$startupHostCode = {

    param($vmToGen, $userOptions)
     
    $esxhost=$userOptions.esxhost
	$username=$userOptions.username
	$password=$userOptions.password
    $masterPassword=$userOptions.masterPassword
	$ds=$userOptions.ds
    $vmPrefix=$userOptions.nestedVMPrefix
    $VM_name="$vmPrefix$($vmToGen.name)"
	$mgmtIP=$vmToGen.mgmtIP

    # Import PowerCLI Module

    Import-Module -Name VMware.VimAutomation.Core

	$WarningPreference = "SilentlyContinue"
	
	write-host "Connecting to $esxhost" -foreground green
    
	$conResult = Connect-viserver $esxhost -user $username -password $password
    if (!$conResult.isConnected) {
		write-host "Unable to connect to vCenter!"
		exit
	}
    write-host "Add CD/ISO $VM_name"
    New-CDDrive -VM $VM_name -ISOPath "[$ds] ISO\VLC_vSphere.iso" -StartConnected:$true -Confirm:$false | Out-Null

	Start-VM -VM $VM_Name | Out-Null
    
    do {
	  write-Host "Waiting for host to install and reboot."$dotBar
	  sleep 30 
	  $dotBar += "."
    } until(Test-NetConnection $mgmtIP -Port 22 | ? { $_.tcptestsucceeded } )
    
    do {
        $ESXiOnline = Get-VM -Name $VM_Name
        logger "Waiting for host to be online."$dotBar
        sleep 30
        $dotBar += "."  
      } until($ESXiOnline.ExtensionData.Guest.ToolsRunningStatus -eq "guestToolsRunning") 

    Write-Host "Host online!"

    $cdDrive = Get-CDDrive -VM $VM_name
    Set-CDDrive $cdDrive -NoMedia -Confirm:$false

}
#endregion Host Startup

#region Main and Custom ISO Generation
# Main Start
	$totalTime = [system.diagnostics.stopwatch]::StartNew()
	$esxhost = $userOptions.esxhost
	$username = $userOptions.username
	$password = $userOptions.password
    $masterPassword=$userOptions.masterPassword
    $dnsServer = $userOptions.dnsServer
    $ntpServer = $userOptions.ntpServer
    $hostDomainName = $userOptions.vcfDomainName

# Parse Host JSONs
$hostsToBuild = New-Object System.Collections.Arraylist
if ($jsonLoc -ne "") {
    $genvms = Get-Content -raw $jsonLoc | ConvertFrom-Json                                                                                                                                                                    
    $genvms.genVM | ForEach-Object -Process {$hostsToBuild.Add($_)} 
}

if ($global:bringUpOptions.hostSpecs) {     

    $genvms = Get-Content -raw "$($global:scriptDir)\default_mgmt_hosthw.json" | ConvertFrom-Json  
    
    $templateHosts = $global:bringupOptions | Select -ExpandProperty hostSpecs
    
    $hostCnt = 0
    
    foreach ($templateHost in $templateHosts){
        $ipInfo = $templateHost.ipAddressPrivate
        
            $hostsToBuild.Add($(New-Object PSObject -Property @{name="$($templateHost.hostname)";cpus="$($genvms.genVM[$($hostCnt)].cpus)";mem="$($genvms.genVM[$($hostCnt)].mem)";disks="$($genvms.genVM[$($hostCnt)].disks)";mgmtip="$($ipInfo.ipAddress)";subnetmask="$(CIDRtoSubnet $($ipInfo.cidr.Split("/")[1]))";ipgw="$($ipInfo.gateway)"}))
            $hostCnt++
    }                                                                                                                                      

}


$numHosts = $hostsToBuild.Count

If (!$chkHostOnly.Checked) {
#region CloudBuilder Import
    # Import CloudBuilder
    logger "Importing CloudBuilder OVF"
    Connect-VIserver $userOptions.esxhost -user $userOptions.username -password $userOptions.password | Out-Null

    $usernameOVF=$userOptions.username
    $passwordOVF=$userOptions.password
    $esxhostOVF=$userOptions.esxhost
    $netNameOVF=$userOptions.netName
    $clusterOVF=$userOptions.cluster
    $netCBIPaddress=$userOptions.cbIPAddress
    $netCBSubnet=$userOptions.mgmtNetSubnet
    $netCBSubnetCidr=$userOptions.mgmtNetCidr
    $netCBGateway=$userOptions.mgmtNetGateway
    $netCBDNS=$userOptions.dnsserver
    $netCBNTP=$userOptions.ntpserver
    $cbPassword=$userOptions.masterPassword
    $vcfDomainName=$userOptions.vcfDomainName
    $dsOVF=$userOptions.ds
    $mgmtVlan = $userOptions.mgmtNetVlan

    $ovfCmd = "$($ovfToolPath)ovftool.exe"

    [System.Collections.ArrayList]$ovfArgs = @(
		    "--name=$CBName" 
		    "--acceptAllEulas" 
		    "--skipManifestCheck"
		    "--X:injectOvfEnv"
		    "--net:`"Network 1=$netNameOVF`""
		    "-ds=`"$dsOVF`""
		    "-dm=thin"
		    "--noSSLVerify" 
		    "--prop:guestinfo.ip0=$netCBIPaddress"
		    "--prop:guestinfo.netmask0=$(CIDRtoSubnet $netCBSubnetCidr)"
		    "--prop:guestinfo.gateway=$netCBGateway"
		    "--prop:guestinfo.hostname=`"$CBName`""
		    "--prop:guestinfo.DNS=$netCBDNS"
		    "--prop:guestinfo.ntp=$netCBNTP"
		    "--prop:guestinfo.ROOT_PASSWORD=`"$cbPassword`""
		    "--prop:guestinfo.ADMIN_USERNAME=`"admin`""
		    "--prop:guestinfo.ADMIN_PASSWORD=`"$cbPassword`""
		    "--X:logLevel=verbose"
		    "--X:logFile=`"$scriptDir\Logs\CBImport-$(get-date -format "yyyymmdd_hhmmss")`""
		    "--powerOn"
		    "`"$CBISOLoc`""
        )
    if ($clusterOVF.Length -eq 0) {
        $ovfArgs.Add("`"vi://${usernameOVF}:${passwordOVF}@${esxhostOVF}`"")
    } else {
        #Get the MoRef of the Cluster in case it has spaces or illegal characters
        $targetCluster = Get-Cluster | Where {$_.Name -eq $clusterOVF}
        $clusterMoref = $targetCluster.ExtensionData.MoRef.Value
        $ovfArgs.Add("`"vi://${usernameOVF}:${passwordOVF}@${esxhostOVF}:443?moref=vim.ClusterComputeResource:${clusterMoref}`"")
    }
    $getKey = "R"
    Do {
        Try{
            $result = Start-Process $ovfCmd -ArgumentList $ovfArgs -Wait -PassThru -NoNewWindow
            if ($result.ExitCode -ne 0) {
                throw $result.ExitCode
            }
            $getKey = ""
        } catch {
            $ovfCmdLine = "`"$ovfCmd`" $($ovfArgs -join ' ')"
            logger "There was a problem importing Cloudbuilder with OVF tool, the process exited with a non zero code: $_`n"
            logger "See VLC Process Window or the CBImport log in $scriptDir\Logs for more info!"
            logger "You can Retry, or run the command below by copying/pasting into another powershell window" -consoleOnly
            logger "---------------------------------------------------------------------------" -consoleOnly
            logger "& $ovfCmdLine`n" -consoleOnly
            $getKey = Read-Host "Enter R to Retry, Enter N to exit, or any other key to Continue after/if the manual import is successful." 
            If ($getKey -ilike 'N') {
                Exit
            }
        }
    } Until ($getKey -inotlike "R")

    # Wait for Cloudbuilder to come online

    do {
          $CBOnline = Get-VM -Name $CBName
	      logger "Waiting for CloudBuilder to be available..."
	      sleep 30  
        } until($CBOnline.ExtensionData.Guest.ToolsRunningStatus -eq "guestToolsRunning")   

    logger "CloudBuilder online!"

    if($global:Ways -match 'externalsvcs' -and $mgmtVlan -ne 0) {

        logger "Setting VLAN on CloudBuilder"
        $replaceNet =""
        $mgmtVlanId = $userOptions.mgmtNetVlan
        $replaceNet +="(`n"
        $replaceNet +="echo [Match]`n"
        $replaceNet +="echo Name=eth0`n"
        $replaceNet +="echo [Network]`n"
        $replaceNet +="echo DHCP=no`n"
        $replaceNet +="echo DNS=$netCBDNS`n"
        $replaceNet +="echo Domains=$vcfDomainname`n"
        $replaceNet +="echo NTP=$netCBNTP`n"
        $replaceNet +="echo VLAN=eth0.$($mgmtVlanId)`n"
        $replaceNet +=")>/etc/systemd/network/10-eth0.network`n"
        $replaceNet +="(`n"
        $replaceNet +="echo [NetDev]`n"
        $replaceNet +="echo Name=eth0.$($mgmtVlanId)`n"
        $replaceNet +="echo Kind=vlan`n"
        $replaceNet +="echo [VLAN]`n"
        $replaceNet +="echo Id=$($mgmtVlanId)`n"
        $replaceNet +=")>/etc/systemd/network/eth0.$($mgmtVlanId).netdev`n"
        $replaceNet +="(`n"
        $replaceNet +="echo [Match]`n"
        $replaceNet +="echo Name=eth0.$($mgmtVlanId)`n"
        $replaceNet +="echo [Network]`n"
        $replaceNet +="echo DHCP=no`n"
        $replaceNet +="echo Address=$netCBIPaddress/$netCBSubnetCidr`n"
        $replaceNet +="echo Gateway=$netCBGateway`n"
        $replaceNet +=")>/etc/systemd/network/eth0.$($mgmtVlanId).network`n"
        $replaceNet +="systemctl restart systemd-networkd`n"
        $cbVlanCMD = Invoke-VMScript -ScriptText "$replaceNet" -ScriptType Bash -GuestUser root -GuestPassword $masterPassword -VM $cbOnline

    }
    
    mkdir $scriptDir\Temp -Force
    
    if($chkUseCBIso.Checked -eq $true) {

        logger "Retrieving ESXi ISO from CloudBuilder, this will take a minute or two..."
        mkdir $scriptDir\cb_esx_iso -Force
        $esxiPath = $(Invoke-VMScript -ScriptText "find /mnt/iso/*/esx_iso -name *.iso | grep visor" -ScriptType Bash -GuestUser admin -GuestPassword $masterPassword -VM $cbOnline).ScriptOutput.Trim()
        $esxiBuild = $($esxiPath.Split("/")[$($esxiPath.Split("/").Count)-1])
        $osEsxiPath = "$scriptDir\Temp\$esxiBuild"
        $copyEsxiPath = "$scriptDir\cb_esx_iso\$esxiBuild"
        If (Test-Path -Path $copyEsxiPath) {
            logger "Matching version of ESXi detected locally, skipping copy from Cloudbuilder and copying from $copyEsxiPath to Temp directory."
            Copy-Item $copyEsxiPath -Destination $osEsxiPath -Recurse
            $vSphereISOLoc = $osEsxiPath
        } else {
            Copy-VMGuestFile -Source $esxiPath -Destination "$scriptDir\Temp\" -VM $CBOnline -GuestToLocal -GuestUser admin -GuestPassword $masterPassword -ToolsWaitSecs 30 -Force
            logger "Making backup copy of the ESXi ISO in $scriptDir\cb_esx_iso\ for future use with Expansion Pack"
            Copy-Item $osEsxiPath -Destination "$scriptDir\cb_esx_iso\" -Recurse
            $vSphereISOLoc = $(Get-ChildItem -Path "$scriptDir\Temp\*.iso" | Select FullName).FullName        
        }
    } else {
        logger "Using ESXi ISO located here: $vSphereISOLoc"
    }
    # Cloud Builder Config
    If ($chkInternalSvcs.Checked) {
        # Configure DNS/NTP/DHCP/BGP on CloudBuilder
        if ($(IS-InSubnet -ipaddress $($userOptions.labGateway) -Cidr $netCBSubnet)) {
            cbConfigurator -CloudBuilderIP $netCBIPaddress -CloudBuilderCIDR $netCBSubnetCidr -CloudBuilderGateway $($userOptions.labGateway) -CBName $CBName -vcfDomainName $vcfDomainName
        } else {
            cbConfigurator -CloudBuilderIP $netCBIPaddress -CloudBuilderCIDR $netCBSubnetCidr -CloudBuilderGateway $netCBGateway -CBName $CBName -vcfDomainName $vcfDomainName
        }
    }

}
#endregion CloudBuilder Import


# Extract ISO and Set permissions

extractvSphereISO($vSphereISOLoc)

Set-ItemProperty $scriptDir\temp\ISO\ISOLINUX.BIN -name IsReadOnly -value $false
Set-ItemProperty $scriptDir\temp\ISO\ISOLINUX.CFG -name IsReadOnly -value $false
Set-ItemProperty $scriptDir\temp\ISO\BOOT.CFG -name IsReadOnly -value $false

# Create Hosts
logger "Starting creation of $numHosts found in JSON and template."

# Init Jobs container
$hostJobs=@()

# Loop and start all create jobs in parallel

ForEach ($hostVM in $hostsToBuild) {

	$jobName=$hostVM.name
	$hostJobs += Start-Job -Name $jobName -ArgumentList $hostVM,$userOptions,$logPathDir -ScriptBlock $createHostCode
	logger "Creating host $($hostVM.name)" "-log"

}

write-host "VCF Lab Constructor Host Creation Start Time: "$(get-date -Format 'hh:mm') -foreground black -background green
$oldPos = $host.UI.RawUI.CursorPosition

Do {
	$host.UI.RawUI.CursorPosition = $oldPos
	
    ForEach ($Job in $hostJobs)
		
    {   
		$babyJob=$Job.ChildJobs[0]

		write-host $(get-date -Format 'hh:mm') $Job.Name "Status: " -foreground green
        $rec = New-Object System.Management.Automation.Host.Rectangle(0,$($host.UI.RawUI.CursorPosition.Y-1),10,$($host.UI.RawUI.CursorPosition.Y-1))
        $currentStateGrab = $host.UI.RawUI.GetBufferContents($rec)
        $currentState = ""
        foreach ($curChar in $currentStateGrab) { $currentState = $currentState + $curChar}
        if (!($currentState -match $babyJob.Information)) {
            $overWrite = $host.UI.RawUI.CursorPosition
            [Console]::Write("{0, -$($Host.UI.RawUI.BufferSize.Width)}" -f " ")
            $host.UI.RawUI.CursorPosition = $overWrite
        }

        if ($babyJob.Information.Count -gt 0) {
		    write-host $babyJob.Information.Item($($babyJob.Information.Count)-1)
        } else {
            write-host "Initializing Job..."
        }
    }

    Start-Sleep -Seconds 5

} Until (($hostJobs | Where State -eq "Running").Count -eq 0)

Remove-Job -Job $hostJobs

write-host "All hosts created, starting additional config."
logger "Nested Hosts Creation Time: $($totalTime.Elapsed)"
# Build case statements
Connect-viserver $esxhost -user $username -password $password

$caseStatement = "case `$MAC_ADDR in`n"

foreach ($hostVM in $hostsToBuild) {

	$hostVMName = "$global:VMPrefix$($hostVM.name)"
    $hostFQDN = "$($hostVM.Name).$hostDomainName"
    $hostMgmtIP = $hostVM.mgmtip
    $hostSubnet = $hostVM.subnetmask
    $hostGW = $hostVM.ipgw
    $hostNetAdapter = Get-NetworkAdapter -VM $hostVMName
	$hostMacAddress = $hostNetAdapter[0].MacAddress
    $GBguestdisks=$hostVM.disks.split(',')
        
    $caseStatement+="`t$hostMacAddress)`n"
    $caseStatement+="`t`tIPADDR=`"${hostMgmtIP}`"`n"
    $caseStatement+="`t`tIPGW=`"${hostGW}`"`n"
    $caseStatement+="`t`tSUBNET=`"${hostSubnet}`"`n"
    $caseStatement+="`t`tVM_NAME=`"${hostFQDN}`"`n"
    $caseStatement+="`t`tDNS=`"${dnsServer}`"`n"
    $caseStatement+="`t;;`n"

}

$caseStatement+="esac`n"

# Create Custom vSphere ISO

if ( -not (Test-Path ($scriptDir + "\temp\ISO"))) {
    mkdir -Path "$scriptDir\temp\ISO" -Force

}

logger "Setting ISOLINUX.CFG info... "

$isoLinuxCFG="DEFAULT MBOOT.C32`n"
$isoLinuxCFG+="  APPEND -c BOOT.CFG`n"

byteWriter $isoLinuxCFG "ISO\ISOLINUX.CFG"

logger "Setting BOOT.CFG info...                "

$curBootCFG = Get-Content "$scriptDir\temp\ISO\BOOT.CFG"
$bootCFGCount = 0 
foreach ($bootCfgLine in $curBootCFG) {

    if ($bootCfgLine.Contains("kernelopt")) {

        $curBootCFG[$bootCFGCount] = $curBootCFG[$bootCFGCount] + " ks=cdrom:/VLC.CFG"

        }
        $bootCFGCount++

}
$curBootCFG | Set-Content "$scriptDir\temp\ISO\BOOT.CFG"
			
logger "Setting VLC.cfg info...                "
	
$kscfg="#VCF Scripted Nested Host Install`n"
$kscfg+="vmaccepteula`n"
$kscfg+="rootpw $masterPassword`n"
$kscfg+="install --firstdisk --novmfsondisk`n"
$kscfg+="reboot`n"
$kscfg+="`n"
$kscfg+="%include /tmp/hostConfig`n"
$kscfg+="`n"
$kscfg+="%pre --interpreter=busybox`n"
$kscfg+="MAC_ADDR=`$(localcli network nic list | awk '/vmnic0/' |  awk '{print `$8}')`n"
$kscfg+="echo `"Found MAC: `${MAC_ADDR}`" > /tmp/found.mac`n"
$kscfg+="${caseStatement}`n"
$kscfg+="echo `"network --bootproto=static --addvmportgroup=true --device=vmnic0 --ip=`${IPADDR} --netmask=`${SUBNET} --gateway=`${IPGW} --nameserver=`${DNS} --hostname=`${VM_NAME}`" > /tmp/hostConfig`n"
$kscfg+="%firstboot --interpreter=busybox`n"
$kscfg+="# SSH and ESXi shell`n"
$kscfg+="vim-cmd hostsvc/enable_ssh`n"
$kscfg+="vim-cmd hostsvc/start_ssh`n"
$kscfg+="# Add Network Portgroup`n"
if($($userOptions.mgmtNetVlan) -eq 0) {
    $kscfg+="esxcli network vswitch standard portgroup add --portgroup-name `"VM Network`" --vswitch-name vSwitch0`n"
} else {
    $kscfg+="esxcli network vswitch standard portgroup add --portgroup-name `"VM Network`" --vswitch-name vSwitch0`n"
    $kscfg+="esxcli network vswitch standard portgroup set --vlan-id=$($userOptions.mgmtNetVlan) --portgroup-name `"Management Network`"`n"
}
$kscfg+="esxcli network vswitch standard set -v vSwitch0 -m 9000`n"
$kscfg+="esxcli network ip interface set -i vmk0 -m 9000`n"
$kscfg+="esxcli system hostname set --fqdn=`${VM_NAME}`n"
$kscfg+="# Setup VSAN`n"
$kscfg+="esxcli system settings advanced set -o /VMFS3/HardwareAcceleratedLocking -i 1`n" 
$kscfg+="esxcli system settings advanced set -o /LSOM/VSANDeviceMonitoring -i 0`n"
$kscfg+="esxcli system settings advanced set -o /LSOM/lsomSlowDeviceUnmount -i 0`n"
$kscfg+="esxcli system settings advanced set -o /VSAN/SwapThickProvisionDisabled -i 1`n"
$kscfg+="esxcli system settings advanced set -o /VSAN/FakeSCSIReservations -i 1`n"
$kscfg+="esxcli storage nmp satp rule add --satp=VMW_SATP_LOCAL --device mpx.vmhba0:C0:T1:L0 --option `"enable_ssd`"`n"

for ($i=2; $i -le ($GBguestdisks.Count-1); $i++) {

#    if ($global:allFlashBuild -eq $true) {
    $kscfg+="esxcli storage nmp satp rule add --satp=VMW_SATP_LOCAL --device mpx.vmhba0:C0:T${i}:L0 --option `"enable_ssd`"`n"
    $kscfg+="esxcli vsan storage tag add -d=mpx.vmhba0:C0:T${i}:L0 -t=capacityFlash`n"
#    } else {
#    $kscfg+="esxcli storage nmp satp rule add --satp=VMW_SATP_LOCAL --device mpx.vmhba0:C0:T${i}:L0 --option `"disable_ssd`"`n"
#    }
}
$kscfg+="esxcli vsan storage automode set --enabled=false`n"
$kscfg+="vim-cmd hostsvc/datastore/destroy datastore1`n"
$kscfg+="esxcli network firewall ruleset set --ruleset-id=ntpClient -e true`n"
$kscfg+="echo 'server $ntpServer' >> /etc/ntp.conf`n"
$kscfg+="/sbin/chkconfig ntpd on`n"
#$kscfg+="/etc/init.d/ntpd restart`n"
$kscfg+="reboot -d 1`n"
	
byteWriter $kscfg "ISO\VLC.CFG"

$isoExe = "$scriptDir\mkisofs.exe"
$scriptDirUnix = $scriptDir.Replace("\","/")
$isoExeArg = "-relaxed-filenames -J -o '$scriptDir\Temp\VLC_vSphere.iso' -b ISOLINUX.BIN -c BOOT.CAT -no-emul-boot -boot-load-size 4 -boot-info-table -ldots '$scriptDirUnix/temp/ISO'"

Invoke-Expression -command "& '$isoExe' $isoExeArg" | out-null

$ds = Get-Datastore $userOptions.ds
logger "Uploading Custom vSphere ISO to the \ISO directory of $($ds)"
New-PSDrive -Name vsands -PSProvider VimDatastore -Datastore $ds -Root "/"
$isoDir = "vsands:\ISO"
if (!$isoDir) {
    mkdir "vsands:\ISO"
}

Copy-DatastoreItem ("$scriptDir\Temp\VLC_vSphere.iso")  "vsands:\ISO\VLC_vSphere.iso" -Force
Remove-PSDrive -Name "vsands"

$hostJobs=@()
$userOptions = $global:userOptions

# Loop and start all create jobs in parallel

foreach ($hostVM in $hostsToBuild) {

	$jobName=$hostVM.name
    $hostJobs += Start-Job -Name $jobName -ArgumentList $hostVM,$userOptions -ScriptBlock $startupHostCode
	logger "Starting up $($hostVM.name)" "-log"
}

write-host "VCF Lab Constructor Host Startup Start Time: "$(get-date -Format 'hh:mm') -foreground black -background green
$oldPos = $host.UI.RawUI.CursorPosition

Do {
	$host.UI.RawUI.CursorPosition = $oldPos
	
    ForEach ($Job in $hostJobs)
		
    {   
		$babyJob=$Job.ChildJobs[0]

		write-host $(get-date -Format 'hh:mm') $Job.Name "Status: " -foreground green
        $rec = New-Object System.Management.Automation.Host.Rectangle(0,$($host.UI.RawUI.CursorPosition.Y-1),10,$($host.UI.RawUI.CursorPosition.Y-1))
        $currentStateGrab = $host.UI.RawUI.GetBufferContents($rec)
        $currentState = ""
        foreach ($curChar in $currentStateGrab) { $currentState = $currentState + $curChar}
        if (!($currentState -match $babyJob.Information)) {
            $overWrite = $host.UI.RawUI.CursorPosition
            [Console]::Write("{0, -$($Host.UI.RawUI.BufferSize.Width)}" -f " ")
            $host.UI.RawUI.CursorPosition = $overWrite
        }

        if ($babyJob.Information.Count -gt 0) {
		    write-host $babyJob.Information.Item($($babyJob.Information.Count)-1)
        } else {
            write-host "Initializing Job..."
        }
    }
	
    Start-Sleep -Seconds 5

} Until (($hostJobs | Where State -eq "Running").Count -eq 0)

Remove-Job -Job $hostJobs

logger "All hosts online, starting additional config."
logger "Nested Hosts Online Time: $($totalTime.Elapsed)"

#endregion Custom ISO Generation

#endregion Imaging

logger "Total Time for Imaging: $($totalTime.Elapsed)"

#endregion Cloud Builder Config
#region Bringup
If ($bringupAfterBuild) {

    $x=0
    logger "Waiting for bringup to start"

    do {

        $bringupAbout = Invoke-Plink -remoteHost $netCBIPaddress -login "admin" -passwd $cbPassword -command "curl -v http://localhost:9080/bringup-app/bringup/about"| ConvertFrom-Json
        write-host "$($bringupAbout.name) - Try # $x"
        SLEEP 10
        $x++

    } until ($bringupAbout.name -eq "BRINGUP")
 
    $inputJson = Get-Content -Raw $global:VCFEMSFile

    logger "Compiling and writing REST API calls"

    $skipSSLFlag = ""
    if ($global:psVer -lt 7) {

    #Ignore Self Signed Cert code for Powershell 5/6 - Thanks x0n - https://stackoverflow.com/users/6920/x0n
    if (-not("dummy" -as [type])) {
        add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
    
public static class Dummy {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }
    
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
    }
}
"@
}    
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()

    } else {
        $skipSSLFlag = @{SkipCertificateCheck=$true}
    }

    #Setup Credentials
    $pwd = ConvertTo-SecureString "$cbPassword" -AsPlainText -Force
    $cred = New-Object Management.Automation.PSCredential ('admin', $pwd)
    
    #Setup Parameters for REST calls

    logger "POSTing Validation REST statement - You will be able to log in to Cloud Builder in 20 minutes to see bringup tasks @ https://$netCBIPaddress/bringup-result"
    $validationAPIParms = @{
        Uri         = "https://$netCBIPaddress/v1/sddcs/validations"
        Method      = 'POST'
        Body        = $inputJson
        ContentType = 'application/json'
        Credential = $cred
    }

    $validationAPIReturn = Invoke-RestMethod @validationAPIParms @skipSSLFlag

    logger $validationAPIReturn -logOnly

    logger "POSTing bringup REST statement"
    $bringupAPIParms = @{
        Uri         = "https://$netCBIPaddress/v1/sddcs"
        Method      = 'POST'
        Body        = $inputJson
        ContentType = 'application/json'
        Credential = $cred
    }

    $bringupReturn = Invoke-RestMethod @bringupAPIParms @skipSSLFlag

    logger $bringupReturn -logOnly

    logger "Waiting for bringup to complete"

    $currTask = ""
    $thisTask = ""
    $retries = 0

    $bringupExecUri = "https://$netCBIPaddress/v1/sddcs/$($bringupReturn.id)"
    $bringupExecParms = @{
        Uri         = $bringupExecUri
        Method      = 'GET'
        ContentType = 'application/json'
        Credential = $cred
    } 

    do {

        $bringupExec = Invoke-RestMethod @bringupExecParms @skipSSLFlag

        if ($bringupExec.status -eq "COMPLETED_WITH_FAILURE") {

            if ($retries -gt 5) {

                logger "Failed Bringup on this task: $($currTask.name) after 7 retries."
                logger "See the log on CloudBuilder for more information"
                logger "SSH or console to $netCBIPaddress username admin, password $cbPassword"
                logger "Log is located at /var/log/vmware/vcf/bringup/vcf-bringup-debug.log"
                logger "You may be able to fix the issue and retry without starting over, see VLC-Slack #vlc-support to ask questions"
                Read-Host "Your VCF SDDC setup failed after 7 retries. Press enter to continue!"
                EXIT
 <#           } elseif ($retries -eq 1) {

                logger "Bringup is having a problem on this task: $($currTask.name) after a retry."
                logger "See the log on CloudBuilder for more information"
                logger "SSH or console to $netCBIPaddress username admin, password $cbPassword"
                logger "Log is located at /var/log/vmware/vcf/bringup/vcf-bringup-debug.log"
                logger "If this is a license key issue, please correct the key in the JSON file you used and save it."
                $getKey = Read-Host "Press R to resubmit the JSON with corrected license key, or Enter to continue without resubmitting the JSON."
                
                if($getKey -ilike 'R') {
                    $inputJson = Get-Content -Raw $global:VCFEMSFile
                    $bringupRetryParams = @{
                        Uri         = $bringupExecUri
                        Method      = 'PATCH'
                        Body        = $inputJson
                        ContentType = 'application/json'
                        Credential = $cred
                    }
                    Invoke-RestMethod @bringupRetryParams
                    $retries = 0
                }
#>
            } else {

            logger "Failure detected on this task: $($currTask.description), retrying."
            <#$cmdPatch = Invoke-Plink -remoteHost $netCBIPaddress -login "admin" -passwd $cbPassword -command "curl -X PATCH http://localhost:9080/bringup-app/bringup/sddcs/$($bringupReturn.id)"
            Invoke-Expression -command $cmdPatch#>
            $bringupRetryParams = @{
                Uri         = $bringupExecUri
                Method      = 'PATCH'
                ContentType = 'application/json'
                Credential = $cred
            }
            Invoke-RestMethod @bringupRetryParams @skipSSLFlag
            $retries ++
            }

        } else {

            $currTask = $bringupExec | Select -ExpandProperty sddcSubTasks | where-object {$_.status -eq "IN_PROGRESS"} | Select name

            if ($($currTask.name) -ne $thisTask -and $($currTask.name) -ne "") {
    
                logger "Bringup current task: $($currTask.name)"
                $thisTask = $($currTask.name)

                }

                Start-Sleep 10

            }
    } until ($bringupExec.status -eq "COMPLETED_WITH_SUCCESS")

#Deployment complete, change Domain manager to deploy less/smaller NSX and vCenter/Disable VMmonitoring in HA/Set DRS to most conservative

logger "Setting DomainManager Lab Sizing and rebooting SDDC Manager"

$domainManagercfg="echo `"$($userOptions.masterPassword)`" | sudo su - <<END`n"
$domainManagercfg+="(`n"	
$domainManagercfg+="echo \#VLC Lab sizing entries`n"
$domainManagercfg+="echo nsxt.manager.formfactor=small`n"
$domainManagercfg+="echo nsxt.manager.wait.minutes=45`n"
$domainManagercfg+="echo nsxt.manager.cluster.size=1`n"
$domainManagercfg+="echo nsxt.management.resources.validation.skip=true`n"
$domainManagercfg+="echo vc7.deployment.option:tiny`n"
$domainManagercfg+=")>>/opt/vmware/vcf/domainmanager/config/application-prod.properties`n"
$domainManagercfg+="END`n"
$domainManagercfg+="shutdown -r`n"

bytewriter $domainManagercfg "DomainManagerConfig.bash"

$sddcManagerVM = $($Global:bringupOptions | Select -ExpandProperty sddcManagerSpec | Select hostname).hostname
$managementVC = $($Global:bringupOptions | Select -ExpandProperty vCenterSpec | Select vcenterHostname).vcenterHostname
$managementVCIP = $($Global:bringupOptions | Select -ExpandProperty vCenterSpec | Select vcenterIp).vcenterIp
$mgmtClusterName = $($Global:bringupOptions | Select -ExpandProperty clusterSpec | Select clusterName).clusterName
$nsxMgtVM = $($Global:bringupOptions | Select -ExpandProperty nsxtSpec | Select -ExpandProperty nsxtManagers | Select hostname).hostname 
$ssoDomain = $($Global:bringUpOptions | Select -ExpandProperty pscSpecs | Select -ExpandProperty pscSsoSpec | Select ssoDomain -Unique).ssoDomain
$ssoAdminPassword = $($Global:bringUpOptions | Select -ExpandProperty pscSpecs | Select adminUserSsoPassword -Unique).adminUserSsoPassword
$ssoCredential = "administrator@$ssoDomain"

Disconnect-VIServer * -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

$i=0
$status=0
do {
    try {
       Write-host "Connecting to Nested vCenter, please wait.." -ForegroundColor green
       #Connect to vCenter
       $conVcenter = Connect-viserver $managementVCIP -user $ssoCredential -password $ssoAdminPassword -ErrorAction Stop | Out-Null
       logger "Connected to vCenter"
       $i=5
    } catch [Exception]{
       $status = 1
       $exception = $_.Exception
       logger "Could not connect to nested vCenter, try #$i"
       $msg = "Could not connect to vCenter, pausing for 1 minute.`n"
       logger "$msg $status $($exception.Message)"
       $i++
       sleep 60
    } Finally {
       if ($status -eq 1){
           logger "[Warning] Unable to connect to the nested vCenter after 5 retries, check to ensure you can resolve it's FQDN."
           logger "You will need to copy and execute the DomainManagerConfig.bash shell script located in the $scriptDir\temp directory to SDDC Manager to keep resource usage low when creating workload domains"
       }

    }
} while ($i -lt 5)

Copy-VMGuestFile -Server $managementVCIP -Source "$scriptDir\Temp\DomainManagerConfig.bash" -Destination "/home/vcf/" -LocalToGuest -VM $sddcManagerVM -GuestUser root -GuestPassword $($userOptions.masterPassword) -Force

Invoke-VMScript -ScriptType Bash -Server $managementVCIP -GuestUser root -GuestPassword $($userOptions.masterPassword) -VM $sddcManagerVM -ScriptText "chmod 777 /home/vcf/DomainManagerConfig.bash;/home/vcf/DomainManagerConfig.bash;systemctl restart domainmanager"
logger "Removing Memory reservation on NSX Manager"
Get-VM -Server $conVcenter -Name $nsxMgtVM | Get-VMResourceConfiguration |Set-VMResourceConfiguration -MemReservationGB 0
logger "Disabling VM Monitoring in HA and setting DRS to conservative" 
configDrsHACluster $(Get-Cluster -Server $conVcenter -Name $mgmtClusterName)
Disconnect-VIServer * -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

}

#endregion Bringup
Disconnect-VIServer * -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
$totalTime.Stop()
logger "Total RunTime: $($totalTime.Elapsed)"
Read-Host "Your VCF SDDC setup is complete. Press enter to continue!"


