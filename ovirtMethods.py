#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#############################################################################
# ovirtMethods.py  -  Python3 script					    #
# ---									    #
# Github @ks86477							    #
# Date: April 13, 2020							    #
#############################################################################

#############################################################################
# Script Description						            #
# ---								            #
# This script handles the creation of an oVirt API session, using the	    #
# username and password to create an oVirt API session, returning the	    #
# authentication token so another script (like ShutNicOfIP) can call this   #
# script to create a new oVirt API session, and use the returned auth token #
# to communicate with the API in the same session			    #
#									    #
# Note: to communicate with the API, the ovirt Manger's cetificate	    #
# (ovirt.crt) must be exported, and stored in the same folder as this	    #
# script, and any script that interacts with the API, like ShutNicOfIP.py.  #
# Note when running requests.post, one parameter is "verify='ovirt.crt'",   # 
# indicating to use that certificate file to secure the request.            #
#############################################################################

import requests
import json

#Username, password, and ovirt URL

APIusername = 'admin'
APIpassword = 'password'
APIurl = 'https://ovirt-engine.projectlab.com' #**Ensure DNS record to IP address of oVirt Manager is created**

#Method to obtain Authentication token for session with the ovirt-engine api
def getAuthToken():
	#Define parameters for Post request to ovirt engine
	authUrl= APIurl + '/ovirt-engine/sso/oauth/token'
	authHeader = {'content-type': 'application/x-www-form-urlencoded',
			      'accept': 'application/json' }
	authBody = 'grant_type=password&scope=ovirt-app-api&username=' + APIusername + '%40internal&password=' + APIpassword
	
	#Send the request to obtain auth token
	authResponse = requests.post(authUrl, data=authBody, headers=authHeader, verify='ovirt.crt')
	authResponseJson = authResponse.json()

	#Parse out auth token and return it, allowing another script to use this token to communicate with the oVirt API 
	authToken = authResponseJson['access_token']
	return authToken
