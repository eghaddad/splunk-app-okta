import sys
import xml.dom.minidom
import xml.sax.saxutils
import logging
import splunk.entity as entity
import httplib
import authSession
import csv
import os
import time, datetime, calendar
import urllib, urllib2
import json
import splunk.clilib.cli_common
import StringIO
import re
import hashlib, md5
import time

from xml.etree.ElementTree import ElementTree

#set up logging suitable for splunkd comsumption
logging.root
logging.root.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)


SCHEME = """<scheme>
    <title>Okta Object</title>
    <description>Get data Okta API</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>simple</streaming_mode>
    <endpoint>
        <args>
            <arg name="name">
                <title>Name</title>
                <description>Choose an ID or nickname for this configuration.</description>
            </arg>

            <arg name="start_date">
                <title>Query Start Date</title>
                <description>Accepted format is "YYYY-MM-DDThh:mm:ss.000z". Keep blank and it defaults to 365 days. Applies only for events data input</description>
                <required_on_create>false</required_on_create>
                <required_on_edit>false</required_on_edit>

            </arg>

            <arg name="time_key">
                <title>Time Field</title>
                <description>The field used to represent the event time</description>
            </arg>

            <arg name="limit">
                <title>Page Size</title>
                <description>Specifies the number records per page</description>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

def do_scheme():
        print SCHEME

def print_error(s):
    print "<error><message>%s</message></error>" % xml.sax.saxutils.escape(s)

def validate_conf(config, key):
    if key not in config:
        raise Exception, "Invalid configuration received from Splunk: key '%s' is missing." % key

#read XML configuration passed from splunkd
def get_config():
    config = {}

    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement
        
        session_key_node = root.getElementsByTagName("session_key")[0]
        if session_key_node and session_key_node.firstChild and session_key_node.firstChild.nodeType == session_key_node.firstChild.TEXT_NODE:
            data = session_key_node.firstChild.data
            config["session_key"] = data

        if session_key_node and session_key_node.firstChild and session_key_node.firstChild.nodeType == session_key_node.firstChild.TEXT_NODE:
            data = session_key_node.firstChild.data
            config["session_key"] = data

        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            logging.debug("XML: found configuration")
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    logging.debug("XML: found stanza " + stanza_name)
                    config["name"] = stanza_name

                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            config[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if checkpnt_node and checkpnt_node.firstChild and checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            config["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not config:
            raise Exception, "Invalid configuration received from Splunk."

        if not config.has_key("start_date"):
            # No start_date was specified for the input, so set the start date to 365 days prior to today
            logging.debug("config has no start_date")
            config["start_date"] = (datetime.date.today() - datetime.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S.000z")

            logging.debug("config['start_date'] is %s" % config["start_date"])

        # just some validation: make sure these keys are present (required)
        validate_conf(config, "name")
        validate_conf(config, "limit")
        validate_conf(config, "checkpoint_dir")
        validate_conf(config, "session_key")
        

    except Exception, e:
        raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

    return config

def get_validation_data():
    val_data = {}

    # read everything from stdin
    val_str = sys.stdin.read()

    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement

    logging.debug("XML: found items")
    item_node = root.getElementsByTagName("item")[0]
    if item_node:
        logging.debug("XML: found item")

        name = item_node.getAttribute("name")
        val_data["stanza"] = name

        params_node = item_node.getElementsByTagName("param")
        for param in params_node:
            name = param.getAttribute("name")
            logging.debug("Found param %s" % name)
            if name and param.firstChild and param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data

    return val_data


def validate_config():
    try:
        test = ""
    except Exception,e:
        print_error("Invalid configuration specified or no rows returned from the SOQL Query.  Please check your Query.  Details: %s" % str(e))
        sys.exit(1)


def get_encoded_file_path(config):
    # encode the input name (simply to make the file name recognizable)
    input_name = config['name']

    name = ""
    for i in range(len(input_name)):
        if input_name[i].isalnum():
            name += input_name[i]
        else:
            name += "_"

    # MD5 the input name
    m = md5.new()
    m.update(input_name)
    name += "_" + m.hexdigest()

    return os.path.join(config["checkpoint_dir"], name)
    #return os.path.join("events", name)

def get_OktaObject(config, settings, endpoint):

    checkpoint_file = get_encoded_file_path(config)

    try:
        f = open(checkpoint_file,"r")
        last = f.read()
        f.close

        if not last:
            last = config["start_date"]


    except Exception, e:
        logging.error( "Okta: Read Timestamp Exception: %s" % e )
        last = config["start_date"]
        pass


    proxy_url = settings['proxy_url']
    domain=str(settings['endpoint'])

    #decrypt the API key
    sk = config['session_key']
    sessionKey = re.sub(r'sessionKey=', "", sk)
    sessionKey = urllib2.unquote(sessionKey.encode('ascii')).decode('utf-8')

    u, p= authSession.getCredentials(sessionKey, domain)
    api = re.sub("``.*", "", p)

    key="SSWS " + api
    req = urllib2.Request( endpoint, headers = {'Authorization' : key , 'Accept' : 'application/json', 'Content-type' : 'application/json'})

    ## Proxy configuration
    proxy_url = settings['proxy_url']
    timeKey = config['time_key']

    
    if proxy_url != "":
        proxyHandler = urllib2.ProxyHandler({'https': proxy_url})
        proxyOpener = urllib2.build_opener(proxyHandler)
        urllib2.install_opener(proxyOpener)
    
    try:
        response = urllib2.urlopen(req)


        data = json.loads(response.read())


        for e in data:
            for k, v in e.items():
                if k == timeKey:
                    last=v
            t = dict(time_of_event=last)
            s=dict(e.items() + t.items())
            print json.dumps(s)

        f = open(checkpoint_file,"w")
        f.write(last)
        f.close()
    
        link_str = str(response.info().getheader('Link'))
        l = re.search('rel=\"self\",\s<(https://.*)>;\srel=\"next\"', link_str)
        if l:
            link = l.group(1)
        else:
            link="no_more"
        return link
    except Exception, e:
        logging.error("Could not get resutlts %s" % e )
        print "Could not connect to Okta " + str(e)

def run():
    config = get_config()
    settings = splunk.clilib.cli_common.getConfStanza("okta", "okta_endpoint")

    domain=settings['endpoint']
    limit = config['limit']
    okta_object= re.sub(r'okta_object\://', "", str(config['name'].lower()))

    checkpoint_file = get_encoded_file_path(config)
    try:
        f = open(checkpoint_file,"r")
        startDate= f.read()
        f.close
        if not startDate:
            startDate = str(config["start_date"])
        #print "start date is " + str(config["start_date"])


    except Exception, e:
        logging.error( "Okta: Read Timestamp Exception: %s" % e )
        startDate = config["start_date"]

    if (config["name"]!="okta_object://Events"):
        endpoint = 'https://' + str(domain) + '/api/v1/'+ okta_object +  '?limit=' + str(limit)
    
    if (config["name"]=="okta_object://Events"):
        str_endp= str(config["time_key"]) + ' gt \"' + startDate + '\"'
        filter_url=urllib.quote(str_endp)
        endpoint = 'https://' + str(domain) + '/api/v1/'+ okta_object +  '?filter=' + filter_url +  '&limit=' + str(limit)
    
    while (1):
        n= get_OktaObject(config, settings, endpoint)

        if n=="no_more":
            break
        else:
            endpoint = n
            time.sleep(3)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_config()
        elif sys.argv[1] == "--test":
            print 'No tests for the scheme present'
        else:
            print 'You giveth weird arguments'
    else:
        
        run()

    sys.exit(0)


