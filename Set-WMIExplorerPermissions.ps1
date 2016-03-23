<#
.SYNOPSIS
Sets permissions required to access WMI classes on a remote computer running Windows 8.

.DESCRIPTION
Set-WmiExplorerPermissions.ps1 gives the current user the permissions required to access 
WMI classes on a remote computer that is running Windows 8. These permissions are required
to use SAPIEN Technologies, Inc. WMI Explorer on a Windows 8 remote computer.

To use the script, run it locally on the remote computer in an elevated session (Run as administrator). 
Because it gives permission to the current user, be sure that the user account under which the script 
is run is the account that will be running WMI Explorer.

To get script status, use the Verbose parameter.

This script does not apply to remote computers running other versions of Windows.

For more information, see the blog post that describes this script: 
https://wp.me/p3tXTf-2DO

The script has three parts:
1. Enables remote administration.
2. Adds the current user to the Distributed COM Users group.
3. Enables Remote Access to the WMI root namespace and sub-namespaces.

.NOTES
This script was created with the help of the following scripts:
Karl Mitschke -
	https://unlockpowershell.wordpress.com/2009/11/20/script-remote-dcom-wmi-access-for-a-domain-user/
The Scripting Guys -
	http://blogs.technet.com/b/heyscriptingguy/archive/2014/10/03/adding-local-users-to-local-groups.aspx

===========================================================================
 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2015 v4.2.95
 Created on:   	10/20/2015 3:24 PM
 Created by:   	DevinL
 Organization: 	SAPIEN Technologies, Inc.
 Filename:     	Set-WMIExplorerPermissions.ps1
===========================================================================
#>
[CmdletBinding()]
param ()

#Requires -Module NetSecurity
#Requires -RunAsAdministrator
Import-Module NetSecurity

$Computer = $env:COMPUTERNAME

<#
	.SYNOPSIS
		Adds the current user to the Distributed COM Users group.
	
	.DESCRIPTION
		Verifies that the current user has rights to add members to the DCOM Users Group, if
		so then it assigns the group to $Group and the username to $User. If the current user
		doesn't have permission to add users then it throws an error. Finally, if all went
		well, it adds $User to the $Group.
	
	.EXAMPLE
		PS C:\> Add-UserToDCOM
#>
function Add-UserToDCOM {
	if (($Group = [ADSI]"WinNT://$Computer/Distributed COM Users, Group") -and ($User = "WinNT://$Computer/$env:USERNAME, User")) {
		try {
			$Group.Add($User)
		} catch {
			Write-Error "There was an error trying to add $User to the DCOM Users Group:"
			Write-Error $_.Exception.Message
		}
	}
}

<#
	.SYNOPSIS
		Enables the Remote Access permission for members of the Authenticated Users Group on the root namespace & subnamespaces.

	.EXAMPLE
		PS C:\> Set-WMISecurity
	
	.NOTES
		This method was largely constructed by Karl Mitschke on his blog post:
		https://unlockpowershell.wordpress.com/2009/11/20/script-remote-dcom-wmi-access-for-a-domain-user/
		The only changes made were minimal, such as adding CI; in $SDDL to ensure subnamespaces received
		the permissions as well.
#>
function Set-WMISecurity {
	# Assign the SID for Authenticated Users to the $SID var.
	$ID = New-Object System.Security.Principal.NTAccount('Authenticated Users')
	$SID = $ID.Translate([System.Security.Principal.SecurityIdentifier]).toString()
	
	# Permission string - Remote Access across namespace and subnamespaces
	$SDDL = "A;CI;CCWP;;;$SID"
	
	try {
		$Security = Get-WmiObject -ComputerName $Computer -Namespace Root -Class __SystemSecurity
		$Converter = New-Object System.Management.ManagementClass Win32_SecurityDescriptorHelper
		$BinarySD = @($null)
		
		$Result = $Security.PsBase.InvokeMethod('GetSD', $BinarySD)
		$OutSDDL = $Converter.BinarySDToSDDL($BinarySD[0])
		$NewSDDL = $OutSDDL.SDDL += '(' + $SDDL + ')'
		
		$WMIBinarySD = $Converter.SDDLToBinarySD($NewSDDL)
		$WMIConvertedPermissions =, $WMIBinarySD.BinarySD
		
		$Result = $Security.PsBase.InvokeMethod('SetSD', $WMIConvertedPermissions)
	} catch {
		Write-Error "There was an error trying to apply remote access to the root namespace: $($_.Exception.Message)"
	}	
}

<#
	.SYNOPSIS
		Enables the Remote Administration rules in the Windows Firewall.

	.EXAMPLE
		PS C:\> Set-RemoteAdmin

	.NOTES
		Technically netsh firewall is deprecated and shouldn't be used unless needed, and in this 
		case I found it necessary. With a fresh Windows 8 VM there were no rules for 
		"Remote Administration" found when using the correct Set-NetFirewallRule. After running 
		'netsh firewall' the rules would be created and then the Set-NetFirewallRule would work.
		The Out-Null portion simply cuts off the deprecated message so you don't see that while
		running the script.	
#>
function Set-RemoteAdmin
{
	netsh firewall set service remoteadmin enable | Out-Null
}

Write-Verbose "Adding $env:USERNAME to Distributed COM Users Group."
Add-UserToDCOM

Write-Verbose "Enabling Remote Access to the root WMI namespace and sub-namespaces."
Set-WMISecurity

Write-Verbose "Enabling Remote Administration."
Set-RemoteAdmin

Write-Verbose "Completed."

# SIG # Begin signature block
# MIITFgYJKoZIhvcNAQcCoIITBzCCEwMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcFg3fciNudbMG8ksckV6Ulol
# FU2ggg2lMIIEFDCCAvygAwIBAgILBAAAAAABL07hUtcwDQYJKoZIhvcNAQEFBQAw
# VzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNV
# BAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0
# MTMxMDAwMDBaFw0yODAxMjgxMjAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBDQSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO9l
# +LVXn6BTDTQG6wkft0cYasvwW+T/J6U00feJGr+esc0SQW5m1IGghYtkWkYvmaCN
# d7HivFzdItdqZ9C76Mp03otPDbBS5ZBb60cO8eefnAuQZT4XljBFcm05oRc2yrmg
# jBtPCBn2gTGtYRakYua0QJ7D/PuV9vu1LpWBmODvxevYAll4d/eq41JrUJEpxfz3
# zZNl0mBhIvIG+zLdFlH6Dv2KMPAXCae78wSuq5DnbN96qfTvxGInX2+ZbTh0qhGL
# 2t/HFEzphbLswn1KJo/nVrqm4M+SU4B09APsaLJgvIQgAIMboe60dAXBKY5i0Eex
# +vBTzBj5Ljv5cH60JQIDAQABo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBRG2D7/3OO+/4Pm9IWbsN1q1hSpwTBHBgNV
# HSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLm5ldC9yb290LmNybDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQ
# L30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEATl5WkB5GtNlJMfO7FzkoG8IW
# 3f1B3AkFBJtvsqKa1pkuQJkAVbXqP6UgdtOGNNQXzFU6x4Lu76i6vNgGnxVQ380W
# e1I6AtcZGv2v8Hhc4EvFGN86JB7arLipWAQCBzDbsBJe/jG+8ARI9PBw+DpeVoPP
# PfsNvPTF7ZedudTbpSeE4zibi6c1hkQgpDttpGoLoYP9KOva7yj2zIhd+wo7AKvg
# IeviLzVsD440RZfroveZMzV+y5qKu0VN5z+fwtmK+mWybsd+Zf/okuEsMaL3sCc2
# SI8mbzvuTXYfecPlf5Y1vC0OzAGwjn//UYCAp5LUs0RGZIyHTxZjBzFLY7Df8zCC
# BJ8wggOHoAMCAQICEhEhBqCB0z/YeuWCTMFrUglOAzANBgkqhkiG9w0BAQUFADBS
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
# AxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMjAeFw0xNTAyMDMwMDAw
# MDBaFw0yNjAzMDMwMDAwMDBaMGAxCzAJBgNVBAYTAlNHMR8wHQYDVQQKExZHTU8g
# R2xvYmFsU2lnbiBQdGUgTHRkMTAwLgYDVQQDEydHbG9iYWxTaWduIFRTQSBmb3Ig
# TVMgQXV0aGVudGljb2RlIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCwF66i07YEMFYeWA+x7VWk1lTL2PZzOuxdXqsl/Tal+oTDYUDFRrVZUjtC
# oi5fE2IQqVvmc9aSJbF9I+MGs4c6DkPw1wCJU6IRMVIobl1AcjzyCXenSZKX1GyQ
# oHan/bjcs53yB2AsT1iYAGvTFVTg+t3/gCxfGKaY/9Sr7KFFWbIub2Jd4NkZrItX
# nKgmK9kXpRDSRwgacCwzi39ogCq1oV1r3Y0CAikDqnw3u7spTj1Tk7Om+o/SWJMV
# TLktq4CjoyX7r/cIZLB6RA9cENdfYTeqTmvT0lMlnYJz+iz5crCpGTkqUPqp0Dw6
# yuhb7/VfUfT5CtmXNd5qheYjBEKvAgMBAAGjggFfMIIBWzAOBgNVHQ8BAf8EBAMC
# B4AwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6
# Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCQYDVR0TBAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL2dzL2dzdGltZXN0YW1waW5nZzIuY3JsMFQGCCsGAQUF
# BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNv
# bS9jYWNlcnQvZ3N0aW1lc3RhbXBpbmdnMi5jcnQwHQYDVR0OBBYEFNSihEo4Whh/
# uk8wUL2d1XqH1gn3MB8GA1UdIwQYMBaAFEbYPv/c477/g+b0hZuw3WrWFKnBMA0G
# CSqGSIb3DQEBBQUAA4IBAQCAMtwHjRygnJ08Kug9IYtZoU1+zETOA75+qrzE5ntz
# u0vxiNqQTnU3KDhjudcrD1SpVs53OZcwc82b2dkFRRyNpLgDXU/ZHC6Y4OmI5uzX
# BX5WKnv3FlujrY+XJRKEG7JcY0oK0u8QVEeChDVpKJwM5B8UFiT6ddx0cm5OyuNq
# Q6/PfTZI0b3pBpEsL6bIcf3PvdidIZj8r9veIoyvp/N3753co3BLRBrweIUe8qWM
# ObXciBw37a0U9QcLJr2+bQJesbiwWGyFOg32/1onDMXeU+dUPFZMyU5MMPbyXPsa
# jMKCvq1ZkfYbTVV7z1sB3P16028jXDJHmwHzwVEURoqbMIIE5jCCA86gAwIBAgIQ
# D3G+iYSlUr2D5y/ELzPF6DANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJVUzEd
# MBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVj
# IFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5bWFudGVjIENsYXNzIDMgU0hBMjU2
# IENvZGUgU2lnbmluZyBDQTAeFw0xNTA4MTIwMDAwMDBaFw0xODEwMTAyMzU5NTla
# MHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMQ0wCwYDVQQHEwRO
# YXBhMSIwIAYDVQQKFBlTQVBJRU4gVGVjaG5vbG9naWVzLCBJbmMuMSIwIAYDVQQD
# FBlTQVBJRU4gVGVjaG5vbG9naWVzLCBJbmMuMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAwZqUHHSXh4kbcGg4h9gRD7D/ltVG5VI+/n5vfFAuKzcsftm9
# Kgh5kpjZHiuhG90in3qYQ2uYxyErTO1v7+399y+/7vjSh3MKf4VGhY5qieC08bb+
# 3z3zefGDp/9U3nNJj8YDpJ7lJWl4HDU5mnszlfUpKZQUYJ1Lj92EBvDsvukz8DJ2
# SrHwPQYZqL1qZ6v8uVraVVRhOQpFXCDq1QvzMt9xJGd/opRUvMasm0uvm/hS/kuJ
# 0TNtj9s8uKdUiM6KwlYyRZbdz/2B3l+LTjnKiXtkgnMakOLj1W9KjdDVrFDtGVMI
# taxI3yncU1qkSEftPd0+yZaefbnJS/UN2A6UwQIDAQABo4IBYjCCAV4wCQYDVR0T
# BAIwADAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N2
# LnN5bWNiLmNvbS9zdi5jcmwwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMG
# CCsGAQUFBwIBFhdodHRwczovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZ
# DBdodHRwczovL2Quc3ltY2IuY29tL3JwYTATBgNVHSUEDDAKBggrBgEFBQcDAzBX
# BggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0dHA6Ly9zdi5zeW1jZC5jb20w
# JgYIKwYBBQUHMAKGGmh0dHA6Ly9zdi5zeW1jYi5jb20vc3YuY3J0MB8GA1UdIwQY
# MBaAFJY7U/B5M5evfYPvLivMyreGHnJmMB0GA1UdDgQWBBQfoDZC6SEmEF6kHUon
# aYJz2Bv3nDANBgkqhkiG9w0BAQsFAAOCAQEAkKpfG9wjJ0gDATI4KTmQBgt0uiN9
# CWqVVO8P7j4RUANfVrwE0pQWPdtZOSDw3GURL98xWm6Dathkpv/FiGJL/6IRtfJ9
# 6zqfDL6rzI8pRpzWhPyxMMl7AImVfUpcEobJ+dnn2k1j9nF5UipkgapDPJUZqgBb
# UpNw69jKNwY0JCZPMt9CxsIrkxzsHJu072ZsXvYKmrD50GrKlvx5T4M5O4QEzU68
# 3qxfr5cYZzDQeKuH/v85tqg59d5N6tJnZxAjMCL6W24ToG6qQpsXcQRhYtLKR/OH
# q2teSjZhyyXzQEGETTYZA3SDkvjWI1+MlBk7jRyzXnqP2kZPIxLQlQF1hTGCBNsw
# ggTXAgEBMIGTMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jw
# b3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UE
# AxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBAhAPcb6J
# hKVSvYPnL8QvM8XoMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgACh
# AoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAM
# BgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT7zMPTIV+cBTy2T8cAY/MAKo+t
# GDANBgkqhkiG9w0BAQEFAASCAQCFTmu8td5Kv8TNJUlmSN5FncQRyGyMLLl5LZrM
# 8ZI0TnLjrIqmGci2/C2XxMuOuETni42c71BCdzgVmgbfD4A6T3gEXk3t8p0ByxrG
# 1Gt43JB2n+NwUhcJPit7NNng+lYcvKQueCuCv3ukU0y6SuVmEJb4IgRMVc/NLcol
# 8ZjCHMNJkNhBt54/tff3VkGs4a7B7tWJrYzIUyEPqir9YWTDHcdIBon4FG8Z5Hru
# lU1cL/nW1cqNJl9eVAk4Wfdx4giJlzXffE0ojm8fdENeo4AKYd9dYHZ3DJGXV45c
# RVkhEzv7q3xGV0zsI0UkfgAlPX0yhVqXXgnP+R3t+WtT6KkeoYICojCCAp4GCSqG
# SIb3DQEJBjGCAo8wggKLAgEBMGgwUjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEds
# b2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMTH0dsb2JhbFNpZ24gVGltZXN0YW1waW5n
# IENBIC0gRzICEhEhBqCB0z/YeuWCTMFrUglOAzAJBgUrDgMCGgUAoIH9MBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE1MTExMTAzMDIy
# M1owIwYJKoZIhvcNAQkEMRYEFK4lWJt1uN411Ca6/L7NuqtotmeOMIGdBgsqhkiG
# 9w0BCRACDDGBjTCBijCBhzCBhAQUs2MItNTN7U/PvWa5Vfrjv7EsKeYwbDBWpFQw
# UjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNV
# BAMTH0dsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gRzICEhEhBqCB0z/YeuWC
# TMFrUglOAzANBgkqhkiG9w0BAQEFAASCAQBfX8fwRthfuQs+JG3ZxYaQAzcyYFYS
# YsqWxBlj4xKG17rm/6TxJUsOL+bWPb1oZbvJOYgk6UkTUU+inIjO93vKLDOZ264W
# uWXmY5Z3+ZkoyzlQVEaErZi6SRqQGdH3qtUXXYQclZC0/S47DJcTk+vAhzvk8C9z
# fCHlPa9Sb9eXiTmlwL4+0R7VAuIEnIFyBlyt0TBgABWPydvf3pr7eH5DUKGeqjyF
# q3F5VSGY8N/ktBino/w/qqQkZrzvpBsmB5GMoJiXN8Sr+l0OGpo1yxWu8VcmGYkL
# 2Xct6YaRVBK0tBbJsjDAGAkmJxALjvDe/LaUWh7q08QnPsPmJzNk4yZF
# SIG # End signature block
