###########################################
## Created  by Elias Hadadd elias@splunk.com
## version 1.0


import os
import splunk.Intersplunk
import csv, logging, os, sys, time, datetime, calendar, urllib, urllib2, json
import splunk.clilib.cli_common
import xml.dom.minidom, xml.sax.saxutils
import StringIO, re
import authSession
import splunk.admin as admin
import splunk.entity as en
import os
import re
import requests


sk = sys.stdin.readline().strip()

keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()
setting = splunk.clilib.cli_common.getConfStanza("okta", "okta_endpoint")

domain=setting['endpoint']

s = re.search('.*authToken>(.*)<\/authToken>.*', sk)
sessionKey=s.group(1)

sessionKey = urllib2.unquote(sessionKey.encode('ascii')).decode('utf-8')

#get the username and password from app.conf
u, p= authSession.getCredentials(sessionKey, domain)
key = re.sub("``.*", "", p)

user= options.get('user', "None")
max=options.get('max', "None")
if max=="None":
    max=1
i=0
if results:

    if ((user!= "None")):
        for result in results:
            if(i<int(max)):
                if user in result:
                    output_user=result[user]
                else:
                    output_user=user

                key="SSWS " + key
                endpoint = 'https://' + str(domain) + '/api/v1/users/' + user + '/lifecycle/deactivate'


                try:
                    req = requests.post(url=endpoint, headers = {'Authorization' : key , 'Accept' : 'application/json', 'Content-type' : 'application/json'})
                    resp=req.json()
                    s = re.search('.error.*', str(resp))
                    if s:
                        result['deactivate']="Could not deactivate user. Seems like User ID is not valid or user already deactivated"
                    else:
                        result['deactivate']="Success"

                except requests.exceptions.RequestException as e:
                    print "Could not access OKTA API ", e.read()
                    sys.exit(0)
            else:
                break
    else:
        print "Missing Arguments. group and user fields are required"
    splunk.Intersplunk.outputResults(results)
