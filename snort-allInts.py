#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#############################################################################
# snort-allInts.py  -  Python3 script										#
# ---																		#
# Github @ks86477															#
# Date: April 13, 2020														#
#############################################################################

#############################################################################
# Script Description														#
# ---																		#
# This script performs monitoring of ALL interfaces attached to the VM,	by	#
# starting a seperate thread for each interface, running snort on that		#
# interface.  The main method creates a list of all interfaces on the       #
# system, then calls snort_If method for each interface, passing the        #
# interface name and the "violatingIPsDict" dictionary, which is used to 	#
# store the source violating IP addresses, and the number of violations 	#	
# associated with each IP. This same dictionary is shared across all		#
# snort_If threads which are running.  Every 30 seconds, the main method  	#
# checks the dictionary for new violation entries, if any IP addresses		#
# are found surpassing the violation limit, action is taken, calling 		#
# GetViolatingADUser.ps1 to find out if the user is an administator, and	#
# calling DisableADUser.ps1 and ShutNicOfIP.py if the user is not an		#
# administrator.															#
#																			#
# Note: Running this script requires snort and powershell to be installed.  # 														
#        																	#			
#############################################################################


import subprocess  # for opening snort process
import re          # for regex
import time        # for sleep method
import os          # for listing directory contents
import fnmatch     # for searching for specific file
import signal
from datetime import datetime
import json
import _thread	   # for creating snort listening process threads

from subprocess import PIPE, STDOUT


#Import methods from ShutNicOfIP
from ShutNicOfIP import shutNicOfIP

#Command to run for snort monitoring:
# snort -A console -q -i eth1 -c /etc/snort/snort.conf


def main(args):
	
	#Variable to adjust interval in seconds of how often to check the number of violations per source IP
	checkInterval = 30
	
	#Violation limit - perform action if violations exceed below amount within checkInterval
	violationLimit = 50
	
	#Create dict to keep track of IP violations, 
	#pass it to snort_If thread to keep dict of IP addresses, and number of IP violations for each
	violatingIPsDict = dict()
	
	#Get list of all interfaces to snort, removing loopback interface
	ifList = os.listdir('/sys/class/net/')
	ifList.remove('lo')	

	
	#Loop through all interfaces, starting snort listening process for each interface
	for i in ifList:
		
		#start snort_If thread for each interface - pass in the dictionary storing violation counts
		try:
			_thread.start_new_thread(snort_If, (violatingIPsDict, i,))
			print("Started monitoring for interface",i)
		except:
			print("Error: unable to start thread snort_If for int",i)
			exit()
		
	
	
	# Snort listening processes now started on all interfaces, storing results of violating IP addresses in the same
	# dictionary, violatingIPsDict. The following while loop tracks checks the number of violations found in the 
	# dict every 30 seconds (or configured interval). At the end of each loop, the dictionary is reset.
		
		
	#infinite loop on timer to track number of IP violations every x interval seconds
	while(True):
		#sleep for 30 seconds (or interval configured at checkInterval)
		time.sleep(checkInterval)
		
		print("#"*60)	

		#Print out current violations per each IP, perform action if violations exceed limit
		#For loop through each IP address in dictionary
		for ip in violatingIPsDict:
			print("#####")
			print("IP:", ip, "with", violatingIPsDict[ip], "violations.")
			
			#IF the number of violations for this IP exceed the limit, take action!!
			if (violatingIPsDict[ip] > violationLimit):
				
				print("Threshold of", violationLimit, "exceeded by source IP:", ip)
				
				#Get User who violated network policy, and whether the user is an administrator or not
				getAdminProc = subprocess.Popen(["pwsh","GetViolatingADUser.ps1",ip], shell=False, stdout=subprocess.PIPE)
				getAdminProcOutput = getAdminProc.stdout.readlines()			

				#Check if the user is an administrator or not
				#IF user is an administrator, take no action
				#ELSE, user is NOT an administrator, take action, disable the AD account, shut down the violating vNIC
				if (getAdminProcOutput[-1] == b'Admin = True\n'):
					print("No action taken - Admin Logged In")			
				else:
					print("Taking action on host with IP:", ip)
					
					#If the user is not null, get the username from the output, and disable the user account
					if (getAdminProcOutput[-2] != b'nullUser\n'):
						violatingUser = str(getAdminProcOutput[-2]).strip("b'\\n")
	
						#Create powershell process to disable the active directory account of violatingUser
						print("Disabling user account:", violatingUser)
						disableUserProc = subprocess.Popen(["pwsh","DisableADUser.ps1",violatingUser], shell=False, stdout=subprocess.PIPE)
						
					else:
						print("User account to disable not found!")

					#Call ShutNicOfIP to shut down the vNIC of the violating VM
					print("Shutting down vNIC of VM with IP address:", ip)
					shutNicOfIP(ip)
			
			else:
				print("No action taken - Violation count less than", violationLimit)
	
	
		print("#"*60)					
		print("\n\n")
		
		#Reset the dictionary - end of while loop
		violatingIPsDict.clear() 

		
#################################################################################################################################################		
		
	
#Snort Interface method
def snort_If(dict_violatingIPs, if_name):

	#assign the violating IPs dictuonary 
	violatingIPs = dict_violatingIPs
	
	#Assign passed in interface name to a local scope variable
	ifName = if_name	

	#Define regex match for an IP Address
	reIPmatch = re.compile('[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]')

	#Infinite while loop to create a snort monitoring process, read the process output after the max
	#amount of output is reached, parse and count the occurences of each source IP address, and terminate
	#the snort listening process to start a new loop
	while(True):
		
		#Start the snort listening process on interface name ifName
		snortProc = subprocess.Popen(["snort","-A","console","-q","-i",ifName,"-c","/etc/snort/snort.conf"], shell=False, stdout=PIPE)

		#store process output/return in returnData
		returnData = snortProc.stdout

		#Get the output/returned data as a string, store each line of the output in seperate array elements
		returnString = str(returnData.peek(1000))
		returnArray = returnString.split('\\n')

		#Iterate through each line of the output
		for line in returnArray:
			
			#print snort output line to console
			print(line)	
			
			#In the line, retrieve the IP addresses using the regex match of an IP address
			#2 IP addresses are retrived, source and destination IP addresses
			IPmatch = reIPmatch.findall(line)

			#If regex IP search found IP addresses, set the first IP found as the source IP address
			#(the violating IP address)
			if (len(IPmatch) > 0):
				srcIP = IPmatch[0]
				
				#Add the source IP to the violating IPs dictionary
				#If the violating IP is already in the dictionary, add 1 to the violation count
				#If the violating IP is not in the dictionary, add the IP to the dictionary with violation count = 1
				if srcIP in violatingIPs:
					violatingIPs[srcIP] = violatingIPs[srcIP] + 1
				else:
					violatingIPs[srcIP] = 1

		#Print newlines, kill the snort process (since output buffer of process is full,
		#we start a new snort process at beginning of loop
		print("\n\n")
		snortProc.kill()
		

#Run this script from command line
if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
