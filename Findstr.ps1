<#
=============================================================================================
Name:           [Isolated] PowerShell: Fixing Unquoted Service Paths Enumeratoin Vulnerability
Description:    This script displays Unquoted Service Paths Enumeratoin Vulnerabilities on isolated host  


Unquoted service path vulnerabilities are rated as a highly critical vulnerabilities in windows.
If you have the vulnerability scan report with you, the report contains the following information about this reported vulnerability:
Vulnerability Name: Microsoft Windows Unquoted Service Path Enumeration
Vulnerability Synopsis: The remote Windows host has at least one service installed that uses an unquoted service path.
Vulnerability Description: The remote Windows host has at least one service installed that uses an unquoted service path, which contains at least one whitespace. A local attacker can gain elevated privileges by inserting an executable file in the path of the affected service.  Note that this is a generic test that will flag any application affected by the described vulnerability.
Vulnerability Solution: Ensure that any services that contain a space in the path enclose the path in quotes.
Remediation
There are two stages to fix these vulnerabilities
1. finding the unquoted path on the affected host
2. Fixing the unquoted paths 


Run CMD as Administrator > run the command
Copy all the results to a text or excel file
Fixing unquoted service path vulnerabilities 
Search for the unquoted registry entry of the affected service under HKLM\System\CurrentControlSet\Services registry path > Double Click the Image Path key > fix comma like “servicepath” at the beginning and end of the path
Examples:
Unquoted service path: C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe
Quoted service path: "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe" 

============================================================================================
#>
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
