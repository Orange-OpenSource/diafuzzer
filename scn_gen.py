#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from Dia import *
import os
import sys
from cPickle import load
import argparse
import json

assert(os.path.exists('.dia-cache'))
with open('.dia-cache', 'rb') as f:
  d = load(f)

def list_applications(prefix=''):
  for app in d.apps:
    if app.name.startswith(prefix):
      yield app.name

def get_application(appName):
    assert(appName)

    for app in d.apps:
        if app.name == appName:
            return app
    return False

def list_messages(app, prefix=''):
    assert(app)
    for msg in app.msgs:
        if msg.name.startswith(prefix):
            yield msg

def get_message(app, name):
    assert(isinstance(name, int) or isinstance(name, str))
    assert(name)
    for msg in app.msgs:
        if msg.name == name or msg.code == int(name):
            return msg
    return None

def list_avps(msg, prefix=''):
    assert(msg)
    for qavp in msg.avps:
        if qavp.avp and qavp.avp.name.startswith(prefix):
            yield qavp.avp




def main():
    parser = argparse.ArgumentParser(description='Generate a valid Python Msg base structure from the Diameter App ID and the Message Code.')
    
    parser.add_argument('-l',default=None, action='store_true', help="Listing Mode (default). In this mode, the script will list the potentials Applications, Messages or Avps using the provided (or not) --app and --msg args.")
    parser.add_argument('-c', default=None, action='store_true', help="Creation Mode.")
    parser.add_argument('-b', default=False, action='store_true', help="Beautify (default: false). Adapt the output to be printed in a terminal. Make it human-readable.")

    parser.add_argument('--app', 
    help='Select a specific application. Use either the name or the ID of the Application.',
    choices=[a for a in list_applications()])
    parser.add_argument('--msg', 
    help='Select a specific message type. Requires the --app parameter to be defined. Use either the name or the ID of the Application.')
    parser.add_argument('--rmopt', default=False, action='store_true', 
    help='Remove the Optionnals Avps (default: false). Only useful in Creation mode ')



    args = parser.parse_args()
    
    # We can't be in both Creation Mode and Listing Mode at the same time
    assert(not(args.l and args.c))
    
    if args.l is None and args.c is None:
        print >> sys.stderr, "You must chose a mode. Either listing (-l) or creation (-c). See --help for usage informations."
        return -1

    # Listing Mode
    if args.l == True:
        #print("Listing Mode.")
        
        if args.app == None or args.app=="":
            # Beautify mode
            if args.b == True:
                print("Applications List:")
                print("-------------------------------")

                for app in list_applications():
                    print "- %s" % (app)
            # JSON output mode
            else:
                data = [app for app in list_applications()]
                print >> sys.stdout, json.dumps(data)

        else:
            app = get_application(args.app)
            assert(app)
            # We've got the App and we want to list potentials msgs
            if args.msg == None or args.msg=="":
                
                if args.b:
                    print("Messages List for Application <%s>" % app.name)
                    print(b"  ID\t-\tName")
                    print("-------------------------------")
                    for msg in list_messages(app):
                        print(b"- %d\t-\t%s" % (msg.code, msg.name))
                #JSON output Mode
                else:
                    data = [[msg.code, msg.name] for msg in list_messages(app)]
                    print >> sys.stdout, json.dumps(data)

            else:
                msg = get_message(app, args.msg)
                assert(msg)
                # Beautify Mode
                if args.b:
                    print("Avps List for Application <%s> and Msg <%s>" % (app.name, msg.name))
                    print(b"  ID\t-\tName")
                    print("-------------------------------")
                    for avp in list_avps(msg):
                        print(b"- %d\t-\t%s" % (avp.code, avp.name))
                else:
                    data = [[avp.code, avp.name] for avp in list_avps(msg)]
                    print >> sys.stdout, json.dumps(data)
                
    else:
        #print ("Creation Mode")
        if args.app!=None and args.msg !=None and args.app!="" and args.msg!="":

            app = get_application(args.app)
            assert(app)
            msg = get_message(app, args.msg)
            assert(msg)
                        
            data = b"m = Msg(R=True, code=%d, app_id=0x0, avps=[\n" % msg.code
            for avp in list_avps(msg):
                if avp.M:
                    out = b"# %s (datatype:%s) \n" % (avp.name, avp.datatype)
                else:
                    # If the --rmopt is set, do not print optionnals avp
                    if args.rmopt:
                        continue
                    out = b"# OPTIONAL %s (datatype:%s) \n" % (avp.name, avp.datatype)

                out += b"\t Avp(code=%d, " % avp.code
                if avp.M == True:
                    out += b"M=%r, " %avp.M

                if avp.P == True:
                    out += b"P=%r, " %avp.P
                if avp.V == True:
                    out += b"vendor_id=%d, " % avp.vendor_id
                if avp.allows_stacking == True:
                    out += b"avps=[], "
                
                out += b"data=''), \n\n"
                data += out
            data += b"])"

            print >> sys.stdout, data
        else:
            print >> sys.stderr, "In creative mode, both --app and --msg must be defined. See --help for usage informations."
            return -1
if __name__ == '__main__':
    main()
