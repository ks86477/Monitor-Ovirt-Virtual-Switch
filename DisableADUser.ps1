#############################################################################
# DisableADUser.ps1  -  PowerShell Script																		#
# ---																																				#
# Github @ks86477																														#
# Date: April 13, 2020																											#
#############################################################################

#############################################################################
# Script Description																												#
# ---																																				#
# This script takes a username as an argument, remote connects to the       #
# domain controller, and disables that user account on the domain.					#
# 																																					#
#############################################################################


#Get Violating User Argument - the username of the account to disable
$violatingUser = [string]$args[0]

# Define Credentials to Remote Connect via Powershell to the Domain Controller Server
[string]$userName = 'linuxadmin'
[string]$userPassword = 'Password'

# Crete credential Object
[SecureString]$secureString = $userPassword | ConvertTo-SecureString -AsPlainText -Force 
[PSCredential]$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $userName, $secureString

#Management IP Address for Active Directory Server on VLAN 20
$ip20 = '10.0.0.192'


#Connect to Domain Controller - create new session
$adSession20 = New-PSSession -ComputerName $ip20 -Credential $cred -Authentication Negotiate

#Run command on domain controller to disable the user account violating network policy
$disableAccountAD20 = Invoke-Command -Session $adSession20 -Script { param($user) Disable-ADAccount -Identity $user } -Args $violatingUser

echo $disableAccountAD20

exit
