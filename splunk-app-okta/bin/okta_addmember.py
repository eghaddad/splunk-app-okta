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
import requests
import StringIO, re


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
group= options.get('group', "None")
max=options.get('max', "None")
if max=="None":
    max=1
i=0
if results:

    if ((user!= "None") & (group!= "None")):
        for result in results:
            # do it for first 5 events only
            if(i<int(max)):
                if group in result:
                    output_group=result[group]
                else:
                    output_group=group

                if user in result:
                    output_user=result[user]
                else:
                    output_user=user

                key="SSWS " + key
                endpoint = 'https://' + str(domain) + '/api/v1/groups/' + output_group + '/users/' + output_user

                try:
                    req = requests.put( url=endpoint, headers = {'Authorization' : key , 'Accept' : 'application/json', 'Content-type' : 'application/json'})

                    if (req.status_code!=204):
                        result['changegroup']="Could not assign user to a new group. check that user and group are valid and that user is not already in that group" + str(req.json)
                    else:
                        result['changegroup']="Success"

                except requests.exceptions.RequestException as e:
                    print "Could not access OKTA API ", e.read()
                    sys.exit(0)
                i=i+1
            else:
                break
    else:
        print "Missing Arguments. group and user fiels are required"
    splunk.Intersplunk.outputResults(results)
