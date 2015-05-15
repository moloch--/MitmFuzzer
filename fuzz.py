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
from libmproxy.script import concurrent


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
_fuzz_requests = False
_fuzz_responses = False


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


def fuzz_json(content):
    ''' Fuzz a JSON response '''
    with decoded(flow.response):
    resp = json.loads(flow.response.content)
    payload = _payloads.popleft()
    # Put fuzz here
    return json.dumps(resp)


def fuzz_xml(content):
    ''' Fuzz an XML response '''
    root = parseString(content)
    payload = _payloads.popleft()
    # Put fuzz here
    return root.toprettyxml()


def setup_logging(filename='mitmfuzzer.log', level=logging.DEBUG):
    logging.basicConfig(filename=filename,
                        format='[%(levelname)s] %(asctime)s - %(message)s',
                        level=level)
    logging.info("Starting up ...")


def start(context, argv):
    ''' Initial entry point, sets up logging and loads payloads '''
    setup_logging()
    _fuzz_requests = True if "--requests" in argv else False
    _fuzz_responses = True if "--responses" in argv else False
    payload_dir = argv[argv.index("--payloads") + 1]
    if os.path.exists(payload_dir):
        logging.info("Loading payload(s) from %s" % payload_dir)
        load_payload_dir(payload_dir)
    else:
        logging.error("Fuzzing payload directory '%s' does not exist" % (
            payload_dir
        ))
    logging.info("Loaded %d fuzzing payload(s)" % len(_payloads))


def response(context, flow):
    ''' Callback fired upon each response thru the proxy '''
    if not _fuzz_responses:
        return
    try:
        logging.debug("Intercepting a response ...")
        if 'Content-type' in flow.response.headers:
            if flow.response.headers['Content-type'][0].lower() in JSON_MIMES:
                with decoded(flow.response):
                    flow.response.content = fuzz_json(flow.response.content)
            elif flow.response.headers['Content-type'][0].lower() in XML_MIMES:
                with decoded(flow.response):
                    flow.response.content = fuzz_xml(flow.response.content)
            else:
                logging.debug("No fuzzers for content type '%s', skipping." % (
                    flow.response.headers['Content-type'][0])
                )
        else:
            logging.debug("No Content-type header in response")
    except:
        logging.exception("Response callback threw an exception")


@concurrent
def request(context, flow):
    ''' Callback fired upon each request thru the proxy '''
    if not _fuzz_requests:
        return
    try:
        if 'Content-type' in flow.request.headers:
            if flow.request.headers['Content-type'][0].lower() in JSON_MIMES:
                with decoded(flow.request):
                    flow.request.content = fuzz_json(flow.request.content)
            elif flow.request.headers['Content-type'][0].lower() in XML_MIMES:
                with decoded(flow.request):
                    flow.request.content = fuzz_xml(flow.request.content)
            else:
                logging.debug("No fuzzers for content type '%s', skipping." % (
                    flow.request.headers['Content-type'][0])
                )
        else:
            logging.debug("No Content-type header in request")
    except:
        logging.exception("Request callback threw an exception")
