#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#############################################################################
# ShutNicOfIP.py  -  Python3 script											#
# ---																		#
# Github @ks86477															#
# Date: April 13, 2020														#
#############################################################################

#############################################################################
# Script Description														#
# ---																		#
# This script takes an IP address as an argument, and shuts down the		#
# virtual NIC associated with that IP address.							 	#
# This is accomplished by making oVirt API requests to first get a list of  #
# ALL VMs, then retriving info on the NICs of each VM. The NIC info of each #
# VM is searched looking for the violating IP address argument.	 If the 	#
# NIC with the violaitng IP address assigned is found, that NIC is disabled	#	
# using the oVirt API to request the NIC be disabled.						#
#																			#
# Note: The "ovirt-guest-agent" needs to be installed on ALL VMs for this   #
# script to work, as the agent is required to report the assigned IP        #
# addresses to the oVirt Manager. Without this, the violating IP address	#
# will never be found.														#
#############################################################################

import requests
import xml.etree.ElementTree as ET
import json

#import custom python file with methods like getAuthToken()
from ovirtMethods import *


def main(args):
	argIP = str(args[1])
	print("Searching for vNIC with IP ", argIP, "...")
	shutNicOfIP(argIP)
	
	
def shutNicOfIP(argIP):
	#Get Authentication token for session with ovirt API - **uses ovirtMethods.py script**
	authToken = str(getAuthToken())
	
	
	
	#### Get List of VMs ####
	
	#Define Request parameters for getting list of VMs
	url= APIurl + '/ovirt-engine/api/vms'
	header= {'accept': 'application/xml',
		     'authorization': 'x'}
	header['authorization'] = 'Bearer ' + authToken
	
	#Make the GET Request
	response = requests.get(url, headers=header, verify='ovirt.crt')
	vmsRoot = ET.fromstring(response.text)
	
	
	#Create Dictionary of VMnames and their API link to their nics
	# key = VMname, value = API Link to NICS
	nicsDict = {"VMname": "API Link to NICS"}
	nicsDict.pop("VMname")
	
	#For loops to create dictionary entries for nicsDict
	i = 0
	for vms in vmsRoot.findall('vm'):
		#Get name of VM - use as key in dictionary entry
		vmname = (vms.find('name')).text
		#Search through all link elements for link to nics
		for links in vms.findall('link'):
			if (links.attrib['rel'] == "nics"):
				#Create API Link nic dictionary entry
				nics = links	
				nicsDict[vmname] = nics.attrib['href'] 
		i = i + 1
	
		
		
	#Create dictionary - key = IP Address, value = API Link to de-activate NIC
	ipToShutNicBinding = {'IP Address': "API Link to de-activate NIC"}
	ipToShutNicBinding.pop('IP Address')
	
	
	
	
	### Get NIC info of each VM ###
		
	for vm in nicsDict:
		
		#Define Request parameters for getting list of NICs
		url= APIurl + nicsDict[vm]
		header= {'accept': 'application/xml',
				 'authorization': 'x'}
		header['authorization'] = 'Bearer ' + authToken
	
		#Make the GET Request
		response = requests.get(url, headers=header, verify='ovirt.crt')
		nicsRoot = ET.fromstring(response.text)
		
		#Get list of <nic> elements which have an IP address reported via ovirt-guest-agent
		nics = nicsRoot.findall('nic/reported_devices/reported_device/ips/ip/address/../../../../..')
		
		#Loop through all <nic> elements
		for nic in nics:
			#Get name, ips and links elements
			name = nic.find('name').text
			ips = nic.findall('reported_devices/reported_device/ips/ip/address')
			links = (nic.findall('actions/link'))
			
			#Find and save the link to shut down the nic
			shutNicLink = ''
			for link in links:
				if (link.attrib['rel'] == 'deactivate'):
					shutNicLink = link.attrib['href']
			
			#For every IP, add dictionary entry with API link to deactivate the corresponding NIC
			for ip in ips:
				#Build dictionary - key is IP Address, value is link to de-activate NIC
				ipToShutNicBinding[ip.text] = shutNicLink
	
	
	
	### Shut the NIC of the violating IP Address ###
	
	if argIP in ipToShutNicBinding:
		
		print("vNIC with IP", argIP, "found, shutting down vNIC...")

		#Define Request parameters for deactivating NIC
		url= APIurl + ipToShutNicBinding[argIP]
		header= {'accept': 'application/xml',
				 'content-type': 'application/xml',
				 'authorization': 'x'}
		header['authorization'] = 'Bearer ' + authToken
		databody = '<action/>'

		#Make the POST Request
		response = requests.post(url, data=databody, headers=header, verify='ovirt.crt')
		#responseRoot = ET.fromstring(response.text)
		
		print("oVirt API Response:", str(response))
	else:
		print("vNIC with IP", argIP, "NOT FOUND, no action taken.")

	return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))

