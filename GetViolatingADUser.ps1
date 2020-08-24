#############################################################################
# GetViolatingADUser.ps1  -  PowerShell Script								#
# ---																		#
# Github @ks86477															#
# Date: April 13, 2020														#
#############################################################################

#############################################################################
# Script Description														#
# ---																		#
# This script takes an IP address as an argument, and finds the user logged	#
# into the violating PC, by creating a remote PowerShell Session to the 	#
# domain controller, then from there, creating another remote PowerShell    #
# session to the violating PC, where the currently logged in user can be    #
# found.																	#
#																			#
# Note: The remote PC needs to allow PS remote sessions through the         #
# firewall, or have firewall disabled for this script to work               #
#############################################################################


#Get Violating IP Address Argument
$violatingIP = [string]$args[0]

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

#Find the domain object for the computer violating network policy - use the ipv4 address to find the computer
$foundComputerAD20 = Invoke-Command -Session $adSession20 -Script { param($ipAddr) Get-ADComputer -Filter "ipv4address -eq '$ipAddr'" -Properties * | Select-Object -ExpandProperty Name } -Args $violatingIP -ErrorAction 'ignore'



$foundComputer = $null

#Check if a computer was found, if not, return user as nullUser, Admin = False, and exit the script
if ($foundComputerAD20 -notlike "") {
	$foundComputer = $foundComputerAD20
}
else {
	echo "NO PC FOUND!!!"
	echo "nullUser"
	echo "Admin = False"
	exit

}



#Find the user logged into the PC, by logging into the remote session to the domain controller,
#then creating a PowerShell session to the violating PC, finding the logged in user.
$foundFullUser = Invoke-Command -Session $adSession20 -Script {
	#load paramaters passed in as Args at end of command
	param($user, $pass, $comp)
	
	#Define domain admin credentials used to login to violating PC
	[SecureString]$secureString = $pass | ConvertTo-SecureString -AsPlainText -Force
	[PSCredential]$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $secureString
	 
	#Create session to violating PC
	$pcSession = New-PSSession -ComputerName $comp -Credential $cred -Authentication Negotiate
	
	#Run command on violating PC to find the logged in user
	Invoke-Command -Session $pcSession -Script { Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName }} -Args $userName, $userPassword, $foundComputer

	
#Split out the returned domain and username
$foundDomain = $($foundFullUser.split('\'))[0]
$foundUser = $($foundFullUser.split('\'))[1]



#Find the group memberships of the violating user
$userGroups = Invoke-Command -Session $adSession20 -Script {
        param ($user)
	Get-ADUser -Identity $user -Properties MemberOf | Select-Object -ExpandProperty MemberOf} -Args $foundUser

	

#Check if the user belongs to the domain admins group
if ($userGroups -match "CN=Domain Admins") {
	$isAdmin = $true
} else {
	$isAdmin = $false
}


#if user is empty, set user to nullUser
if ($foundUser -like "") {
	$foundUser = "nullUser"
}

#Print info, last 2 lines are parsed by snort-AllInts.py to determine username,
#and to check if the user is an administrator
echo "Info:"
echo "Violating IP = $violatingIP"
echo "Found Computer Hostname = $foundComputer"
echo "Violating User = $foundUser"
echo "Violating Domain = $foundDomain"
echo "$foundUser"
echo "Admin = $isAdmin"

exit
