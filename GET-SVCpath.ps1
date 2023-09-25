<#
=============================================================================================
Name:           [Part 1] PowerShell Fixing Unquoted Service Paths Enumeratoin Vulnerability
Description:    This script will contact a remote machine via the network protocols built into REG.exe. The remote host does not need to be running PowerShell, only the host this script is executed on does. You must be respected as an administrator on the target machine. It will create a custom PowerShell object for each key it locates. Offline machines will have their fields marked “Unavailable”

Computername: Name
Status: Retrieved
Key: \Path\Name
ImagePath: Ltr:\PathValue\Executable Argument(s)



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


You can specify a collection of computers on the command line to interrogate, you can get-content from a text file, or you can pipe objects in that have name/computername parameters. There is an optional parameter to turn progress bars off (-progress “No”), which is used by my parallel wrapper. If you do not include any arguments, it assumes the computername environment variable on the host running the script and only runs locally.

.\Get-SVCPath.ps1 computer1,computer2,computer3
.\Get-SVCPath.ps1 (Get-Content textfile)
Get-ADComputer -filter * | .\Get-SVCPath.ps1

For detailed script http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/
============================================================================================
#>
#GET-SVCpath.ps1
[cmdletbinding()]
	Param ( #Define a Mandatory name input
	[Parameter(
	ValueFromPipeline=$true,
	ValueFromPipelinebyPropertyName=$true, 
	Position=0)]
	[Alias('Computer', 'ComputerName', 'Server', '__ServerName')]
		[string[]]$name = $ENV:Computername,
	[Parameter(Position=1)]
		[string]$progress = "Yes"
	) #End Param
 
Process
{ #Process Each object on Pipeline
	ForEach ($computer in $name)
	{ #ForEach for singular or arrayed input on the shell
	  #Try to get SVC Paths from $computer
	Write-Progress "Done" "Done" -Completed #clear progress bars inherited from the pipeline
	if ($progress -eq "Yes"){ Write-Progress -Id 1 -Activity "Getting keys for $computer" -Status "Connecting..."}
	$result = REG QUERY "\\$computer\HKLM\SYSTEM\CurrentControlSet\Services" /v ImagePath /s 2>&1
	#Error output from this command doesn't catch, so we need to test for it...
	if ($result[0] -like "*ERROR*" -or $result[0] -like "*Denied*")
		{ #Only evals true when return from reg is exception
		if ($progress -eq "Yes"){ Write-Progress -Id 1 -Activity "Getting keys for $computer" -Status "Connection Failed"}
		$obj = New-Object -TypeName PSObject
		$obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $computer
		$obj | Add-Member -MemberType NoteProperty -Name Status -Value "REG Failed"
		$obj | Add-Member -MemberType NoteProperty -Name Key -Value "Unavailable"
		$obj | Add-Member -MemberType NoteProperty -Name ImagePath -Value "Unavailable"
		[array]$collection += $obj
		}	
	else
		{
		#Clean up the format of the results array
		if ($progress -eq "Yes"){ Write-Progress -Id 1 -Activity "Getting keys for $computer" -Status "Connected"}
		$result = $result[0..($result.length -2)] #remove last (blank line and REG Summary)
		$result = $result | ? {$_ -ne ""} #Removes Blank Lines
		$count = 0
		While ($count -lt $result.length)
			{
 			if ($progress -eq "Yes"){ Write-Progress -Id 2 -Activity "Processing keys..." -Status "Formatting $computer\$($result[$count])"}
			$obj = New-Object -Typename PSObject
			$obj | Add-Member -Membertype NoteProperty -Name ComputerName -Value $computer
			$obj | Add-Member -MemberType NoteProperty -Name Status -Value "Retrieved"
			$obj | Add-Member -MemberType NoteProperty -Name Key -Value $result[$count]
			$pathvalue = $($result[$count+1]).Split("", 11) #split ImagePath return
			$pathvalue = $pathvalue[10].Trim(" ") #Trim out white space, left with just value data
			$obj | Add-Member -MemberType NoteProperty -Name ImagePath -Value $pathvalue
 
			[array]$collection += $obj
 
			$count = $count + 2
			} #End While
		} #End Else
	if ($progress -eq "Yes"){Write-Progress -Id 2 "Done" "Done" -Completed}
	Write-Output $collection
	$collection = $null #reset collection
	} #End ForEach
	if ($progress -eq "Yes"){Write-Progress -Id 1 "Done" "Done" -Completed}
 
} #End Process