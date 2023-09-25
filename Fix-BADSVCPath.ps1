<#
=============================================================================================
Name:           [Part 3] PowerShell Fixing Unquoted Service Paths Enumeratoin Vulnerability
Description:    This script accepts input on the pipeline from .\Find-BADSVCPath. The “FixedKey” value from the object is read, properly escaped, and fed to a forced REG ADD. It then updates the object status to “Fixed.” Values not marked bad are simply passed through the pipeline.


Unquoted service path vulnerabilities are rated as a highly critical vulnerabilities in windows.
If you have the vulnerability scan report with you, the report contains the following information about this reported vulnerability:
Vulnerability Name: Microsoft Windows Unquoted Service Path Enumeration
Vulnerability Synopsis: The remote Windows host has at least one service installed that uses an unquoted service path.
Vulnerability Description: The remote Windows host has at least one service installed that uses an unquoted service path, which contains at least one whitespace. A local attacker can gain elevated privileges by inserting an executable file in the path of the affected service.  Note that this is a generic test that will flag any application affected by the described vulnerability.
Vulnerability Solution: Ensure that any services that contain a space in the path enclose the path in quotes.
Remediation
There are two stages to fix these vulnerabilities
1. Dinding the unquoted path on the affected host
2. Fixing the unquoted paths 


From the Pipeline only:
.\Get-SVCPath.ps1 | .\Find-BADSVCPath.ps1 | .\Fix-BADSVCPath.ps1
-or-
.\Get-SVCPath.ps1 | .\Find-BADSVCPath.ps1 | Export-CSV result.csv
Import-CSV result.csv | .\Fix-BADSVCPath.ps1


For detailed script http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/
============================================================================================
#>


#Fix-BADSVCPath.ps1
[cmdletbinding()]
	Param ( #Define a Mandatory input
	[Parameter(
	 ValueFromPipeline=$true,
	 ValueFromPipelinebyPropertyName=$true,
	 Position=0)] $obj
	) #End Param
 
Process
{ #Process Each object on Pipeline
	if ($obj.badkey -eq "Yes"){
		Write-Progress -Activity "Fixing $($obj.computername)\$($obj.key)" -Status "Working..."
		$regpath = $obj.Fixedkey
		$regpath = '"' + $regpath.replace('"', '\"') + '"' + ' /f'
		$obj.status = "Fixed"
		REG ADD "\\$($obj.computername)\$($obj.key)" /v ImagePath /t REG_EXPAND_SZ /d $regpath
		}
	Write-Output $obj
 
} #End Process