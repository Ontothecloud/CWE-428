<#
=============================================================================================
Name:           [Part 2] PowerShell Fixing Unquoted Service Paths Enumeratoin Vulnerability
Description:    This script inspects the objects that result from .\Get-SVCPath for unquoted/improperly quoted service. It will amend the object and mark it “Badkey = Yes” or “BadKey = No”. If a bad key is detected, it will update the “FixedKey” field with the properly quoted path value. This script accepts its input from the pipeline. Values marked unavailable (by offline) are passed through the pipeline. 


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
.\Get-SVCPath.ps1 | .\Find-BADSVCPath.ps1
-or
$Var = .\Get-SVCPath.ps1
$Var | .\Find-BADSVCPath.ps1


For detailed script http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/
============================================================================================
#>
#Find-BADSVCPath.ps1
[cmdletbinding()]
	Param ( #Define a Mandatory input
	[Parameter(
	 ValueFromPipeline=$true,
	 ValueFromPipelinebyPropertyName=$true,
	 Position=0)] $obj
	) #End Param
 
Process
{ #Process Each object on Pipeline
	Write-Progress -Activity "Checking for bad keys: " -status "Checking $($obj.computername)\$($obj.key)"
	if ($obj.key -eq "Unavailable")
	{ #The keys were unavailable, I just append object and continue
	$obj | Add-Member –MemberType NoteProperty –Name BadKey -Value "Unknown"
	$obj | Add-Member –MemberType NoteProperty –Name FixedKey -Value "Can't Fix"
	Write-Output $obj
	$obj = $nul #clear $obj
 
	} #end if
	else
	{
	#If we get here, I have a key to examine and fix
	#We're looking for keys with spaces in the path and unquoted
	#the Path is always the first thing on the line, even with embedded arguments
	$examine = $obj.ImagePath
	if (!($examine.StartsWith('"'))) { #Doesn't start with a quote
		if (!($examine.StartsWith("\??"))) { #Some MS Services start with this but don't appear vulnerable
			if ($examine.contains(" ")) { #If contains space
				#when I get here, I can either have a good path with arguments, or a bad path
				if ($examine.contains("-") -or $examine.contains("/")) { #found arguments, might still be bad
					#split out arguments
					$split = $examine -split " -", 0, "simplematch"
					$split = $split[0] -split " /", 0, "simplematch"
					$newpath = $split[0].Trim(" ") #Path minus flagged args
					if ($newpath.contains(" ")){
						#check for unflagged argument
						$eval = $newpath -Replace '".*"', '' #drop all quoted arguments
						$detunflagged = $eval -split "\", 0, "simplematch" #split on foler delim
							if ($detunflagged[-1].contains(" ")){ #last elem is executable and any unquoted args
								$fixarg = $detunflagged[-1] -split " ", 0, "simplematch" #split out args
								$quoteexe = $fixarg[0] + '"' #quote that EXE and insert it back
								$examine = $examine.Replace($fixarg[0], $quoteexe)
								$examine = $examine.Replace($examine, '"' + $examine)
								$badpath = $true
							} #end detect unflagged
						$examine = $examine.Replace($newpath, '"' + $newpath + '"')
						$badpath = $true
					} #end if newpath
					else { #if newpath doesn't have spaces, it was just the argument tripping the check
						$badpath = $false
					} #end else
				} #end if parameter
				else
					{#check for unflagged argument
					$eval = $examine -Replace '".*"', '' #drop all quoted arguments
					$detunflagged = $eval -split "\", 0, "simplematch"
					if ($detunflagged[-1].contains(" ")){
						$fixarg = $detunflagged[-1] -split " ", 0, "simplematch"
						$quoteexe = $fixarg[0] + '"'
						$examine = $examine.Replace($fixarg[0], $quoteexe)
						$examine = $examine.Replace($examine, '"' + $examine)
						$badpath = $true
					} #end detect unflagged
					else
					{#just a bad path
						#surround path in quotes
						$examine = $examine.replace($examine, '"' + $examine + '"')
						$badpath = $true
					}#end else
				}#end else
			}#end if contains space
			else { $badpath = $false }
		} #end if starts with \??
		else { $badpath = $false }
	} #end if startswith quote
	else { $badpath = $false }
	#Update Objects
	if ($badpath -eq $false){
		$obj | Add-Member -MemberType NoteProperty -Name BadKey -Value "No"
		$obj | Add-Member -MemberType NoteProperty -Name FixedKey -Value "N/A"
		Write-Output $obj
		$obj = $nul #clear $obj
		}
	if ($badpath -eq $true){
		$obj | Add-Member -MemberType NoteProperty -Name BadKey -Value "Yes"
		#sometimes we catch doublequotes
		if ($examine.endswith('""')){ $examine = $examine.replace('""','"') }
		$obj | Add-Member -MemberType NoteProperty -Name FixedKey -Value $examine
		Write-Output $obj
		$obj = $nul #clear $obj
		}	
	} #end top else
} #End Process