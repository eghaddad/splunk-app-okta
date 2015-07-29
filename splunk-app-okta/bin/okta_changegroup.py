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



keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()
setting = splunk.clilib.cli_common.getConfStanza("okta", "default")


domain=setting['endpoint']
key=setting['token']

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
                endpoint = 'https://' + str(domain) + '/api/v1/groups/' + group + '/users/' + user

                try:
                    req = requests.put( url=endpoint, headers = {'Authorization' : key , 'Accept' : 'application/json', 'Content-type' : 'application/json'})
                    resp=req.json()
                    if resp!="":
                        s = re.search('.*error.*', str(resp))
                    if s:
                        result['deactivate']="Could not assign user to a new group. check that user and group are valid and that user is not already in tha group"
                    else:
                        result['deactivate']="Success"

                except requests.exceptions.RequestException as e:
                    print "Could not access OKTA API ", e.read()
                    sys.exit(0)
                i=i+1
            else:
                break
    else:
        print "Missing Arguments. group and user fiels are required"
    splunk.Intersplunk.outputResults(results)