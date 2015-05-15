#!/usr/bin/env python
'''
MITM Fuzzer for use with MITMProxy

Usage:
mitmproxy -s "fuzz.py ./fuzzdb/<foo>"
'''

import os
import json
import logging

from collections import deque
from xml.dom.minidom import parseString
from libmproxy.protocol.http import decoded


JSON_MIMES = [
    'application/json',
    'application/x-javascript',
    'text/javascript',
    'text/x-javascript',
    'text/x-json',
]

XML_MIMES = [
    'application/xml',
    'text/xml',
]


_payloads = deque()


def load_payload_file(path):
    ''' Load a file into the payload deque '''
    logging.info("Loading payloads from file: %s" % path)
    with open(path, 'r') as fp:
        for line in fp:
            _payloads.append(line)


def load_payload_dir(folder):
    '''
    Recursively walk thru directories and load files that end with .txt
    but do not start with a '_' character.
    '''
    for root, dirs, files in os.walk(folder):
        for name in filter(lambda name: name.endswith('.txt'), files):
            path = os.path.join(root, name)
            if not os.path.basename(path).startswith('_'):
                load_payload_file(path)


def fuzz_json(context, flow):
    ''' Fuzz a JSON response '''
    with decoded(flow.response):
        resp = json.loads(flow.response.content)
        payload = _payloads.popleft()
        # Put fuzz here
        return json.dumps(resp)


def fuzz_xml(context, flow):
    ''' Fuzz an XML response '''
    with decoded(flow.response):
        root = parseString(flow.response.content)
        payload = _payloads.popleft()
        # Put fuzz here
        return root.toprettyxml()


def start(context, argv):
    ''' Initial entry point, sets up logging and loads payloads '''
    logging.basicConfig(filename='mitmfuzz.log',
                        format='[%(levelname)s] %(asctime)s - %(message)s',
                        level=logging.DEBUG)
    logging.info("Starting up ...")
    if 1 < len(argv) and os.path.exists(argv[1]):
        logging.info("Loading payload(s) from %s" % argv[1])
        load_payload_dir(argv[1])
    else:
        logging.error("Fuzzing payload directory '%s' does not exist" % (
            argv[1]
        ))
    logging.info("Loaded %d fuzzing payload(s)" % len(_payloads))


def response(context, flow):
    ''' Callback fired upon each response thru the proxy '''
    try:
        logging.debug("Intercepting a response ...")
        if 'Content-type' in flow.response.headers:
            if flow.response.headers['Content-type'][0].lower() in JSON_MIMES:
                flow.response.content = fuzz_json(context, flow)
            elif flow.response.headers['Content-type'][0].lower() in XML_MIMES:
                flow.response.content = fuzz_xml(context, flow)
            else:
                logging.debug("No fuzzers for content type '%s', skipping." % (
                    flow.response.headers['Content-type'][0])
                )
        else:
            logging.debug("No Content-type header in response data")
    except:
        logging.exception("Callback response threw an exception")
