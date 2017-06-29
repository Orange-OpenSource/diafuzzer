#!/usr/bin/python2
# coding: utf8
# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys
import socket as sk
from getopt import getopt
from threading import Thread
import select as sl
import os

import Diameter as dm
from Dia import Directory

from scenario import dwr_handler, load_scenario, MsgAnchor
from mutate import MutateScenario

from collections import namedtuple, OrderedDict
import time
import argparse


local_hostname = 'mme.openair4G.eur'
local_realm = 'openair4G.eur'


def analyze(seq, v, a=0, b=2**24):
    sent = 0
    fuzzs=[]
    for i in range(len(seq)):
        (msg, is_sent) = seq[i]

        if is_sent:
            anchor = MsgAnchor(sent, msg.code, msg.R)
            # browse all the possible AVP codes from a( default =0) to b(default =2^24)
            for c in xrange(a, b):
                s = MutateScenario(anchor, 'Try with the proprietary AVP')
                s.act = lambda this, m, c=c, v=v: this.appendAvp(m, c, v)
            
                yield (c, s)


def testScn(host, port, scenario):
    # run once in order to capture exchanged pdus
    f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    f.connect((host, port))
    (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm)
    if exc_info is not None:
        print >> sys.stderr, '[ERROR] The scenario raised %r' % exc_info
        sys.exit(1)
    f.close()

    return msgs


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description='Fuzz proprietary AVPs in a given range of codes, for a given scenario of messages.') 
    parser.add_argument('scenario',  help='Scenario file used to Fuzz')
    parser.add_argument('target', help="Target's IP address")
    parser.add_argument('-p', dest="port", default=3868, type=int, help='Target\'s Diameter port (default: 3868)')
    parser.add_argument('-m', default="client", choices=['client', 'server'], dest="mode", 
            help="Define the mode of the fuzzing. Either as a client to fuzz a server, or as a server to fuzz clients. (default: client)")
    parser.add_argument('--min', type=int, default=0, help="The minimum AVP code to scan (default: 0)")
    parser.add_argument('--max', type=int, default=2**24, help="The maximum AVP code to scan (default: 2^24)")
    parser.add_argument('--vendor', type=int, default=0, help="The vendor ID to fuzz (default: 0)")
    args = parser.parse_args()
    
    # Check the min/max values
    assert(args.min >= 0 and args.min < args.max)
    assert(args.max <= 2**24)
    
    try:
        scenario = load_scenario(args.scenario, local_hostname, local_realm)
    except:
        print >> sys.stderr, "%s - [ERROR] Unable to load given scenario: %s" % (time.ctime(), args.scenario)
        sys.exit(-1)
    vendor = args.vendor
    mode = args.mode
    host = args.target
    port = args.port

    if mode == 'client':
        # Test the scenario once without fuzzing
        msgs = testScn(host,port,scenario)

        for (m, is_sent) in msgs:
            Directory.tag(m)
        start = time.ctime()
        startT = time.time()
        print("Scan started on %s..." % time.ctime())
        for (i, fuzz) in analyze(msgs, vendor, args.min, args.max):
            endT = time.time()
            m, s = divmod(endT-startT, 60)
            h, m = divmod(m, 60)
            elapsedT = (h,m,s)

            if i % 1000 == 0 and i> args.min:
                percent = ((i-args.min)*100.0)/((args.max - args.min)*1.0)
                print("%s - [INFO] %f%% : AVP %d to %d scanned (over %d) in %d:%d:%d..." % (time.ctime(), percent, i-1000, i, args.max, elapsedT[0], elapsedT[1], elapsedT[2]))

            try: 
                f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
                f.connect((host, port))
                (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm, mutator=fuzz)
                f.close()
            except sk.error as serr:
                print >> sys.stderr, '%s - [ERROR] Connexion broken (%s) for AVP %d' % (time.ctime(), serr, i)
                try:
                    testScn(host, port, scenario)
                except sk.error as serr:
                    print >> sys.stderr, '%s - [ERROR] Connexion definitively broken (%s). I quit.' % (time.ctime(), serr)
                    sys.exit(-1)
                
                continue
            
            # Get the last message returned by fuzz_handler
            # Which is the server's response to the fuzzed message
            response = msgs[-1][0]
            if response.code != msgs[0][0].code:
                print('%s - [NOTI] Weird response (msg code %d) to AVP code %d.' % (time.ctime(), response.code, i))
            #if exc_info is not None:
                #print('Error with AVP %d : %s: %s' % (i, fuzz.description, desc_exc(exc_info)))
        
        print("Scanned finished in %d:%d:%d" % elapsedT)
        print(" - start time : %s." % start)
        print(" - end time : %s" % time.ctime())
    '''
    elif mode == 'server':
        srv = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
        srv.bind((host, port))
        srv.listen(64)

        (f, _) = srv.accept()
        (exc_info, msgs) = dwr_handler(scenario, f)
        if exc_info is not None:
            print('scenario raised %r' % exc_info)
            sys.exit(1)
        f.close()

        for (m, is_sent) in msgs:
            Directory.tag(m)

        fuzzs = analyze(msgs)
        print('generated %d scenarios of fuzzing' % len(fuzzs))

        for fuzz in fuzzs:
            (f, _) = srv.accept()
            (exc_info, msgs) = fuzz_handler(scenario, f, fuzz)
            f.close()

            print('%s: %s' % (fuzz.description, desc_exc(exc_info)))
    '''
