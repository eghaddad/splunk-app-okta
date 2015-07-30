###############
## Elias Haddad ehaddad@splunk.com

import csv, logging, os, sys, time, datetime, calendar, urllib, urllib2, json
import splunk.clilib.cli_common
import xml.dom.minidom, xml.sax.saxutils
import StringIO, re
import authSession

from xml.etree.ElementTree import ElementTree




def get_OktaObject():

    domain="oktaprise.okta.com"
    key="SSWS 00Z8CwOaIEECixCO3j-6WGTNR1xRuLwHYzGdy2LZ3X"
    timeKey="published"

    startDate="2013-07-15T16:00:00.000Z"
    limit=100

    #/api/v1/events?startDate=2013-07-15T16%3A00%3A00.000Z\&limit=3
    endpoint = 'https://' + str(domain) + '/api/v1/events?startDate=' + str(startDate) + '&limit=' + str(limit)
    #print "endpoint= " + endpoint

    req = urllib2.Request( endpoint, headers = {'Authorization' : key , 'Accept' : 'application/json', 'Content-type' : 'application/json'})

    ## Proxy configuration
    #proxy_url = settings['proxy_url']
    proxy_url=""
    if proxy_url != "":
        proxyHandler = urllib2.ProxyHandler({'https': proxy_url})
        proxyOpener = urllib2.build_opener(proxyHandler)
        urllib2.install_opener(proxyOpener)
	
    response = urllib2.urlopen(req)

    #print response.read()
    print "now"

    data = json.loads(response.read())
    for evt in data: 
        print json.dumps(evt)



    numbRec=0
    numbSameTS=1
    for e in data:
        for k, v in e.items():
            if k == timeKey:
                if numbRec>0:
                    prev=last
                last=v
                if numbRec>0:
                    if (last==prev):
                        numbSameTS= numbSameTS + 1
                    else:
                        numbSameTS = 1
        numbRec = numbRec + 1
    last_rec=last
    print "Number of records" + str(numbRec) + " " + str(numbSameTS)

    if (numbRec>0):
        i= numbRec
        #print "printing first batch"
        for e in data:
            for k, v in e.items():
                if k == timeKey:
                    last=v
            if (numbRec>numbSameTS):
                t = dict(time_of_event=last)
                s=dict(e.items() + t.items())
                print json.dumps(s)
            numbRec= numbRec - 1
                

        endpoint2 = 'https://' + str(domain) + '/api/v1/events?startDate=' + str(startDate) + '&limit=' + str(limit)
        req2 = urllib2.Request( endpoint, headers = {'Authorization' : key , 'Accept' : 'application/json', 'Content-type' : 'application/json'})
        #print "endpoint2 = " + endpoint2
        
        try:
            response2 = urllib2.urlopen(req2)

        except Exception, e:
            logging.error("Could not get resutlts %s" % e )

        #print "printing second batch"
        obj2 = json.loads(response2.read())
        for e2 in data:
            t2 = dict(time_of_event=last)
            s2=dict(e2.items() + t2.items())
            print json.dumps(s2)

  


def do_run():
    config = get_config()
    settings = splunk.clilib.cli_common.getConfStanza("okta", "default")
    get_OktaObject(settings)


if __name__ == '__main__':
    do_run()

    sys.exit(0)
