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

def print_app(args):
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

def print_msg(app, args):
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

def print_avp(app, msg, args):
# Beautify Mode
    if args.b:
        print("Avps List for Application <%s> and Msg <%s>" % (app.name, msg.name))
        print(b"  ID\t-\tName")
        print("-------------------------------")
        for avp in list_avps(msg):
            # ignore the non-mandatory avps if args.rmopt is set
            if args.rmopt and not avp.M and \
            not(avp.code in args.addavp):
                continue
            else:
                print(b"- %d\t-\t%s" % (avp.code, avp.name))
                
    else:
        data = list()
        for avp in list_avps(msg):
            # ignore the non-mandatory avps if args.rmopt is set
            if args.rmopt and not avp.M and \
            not(avp.code in args.addavp):
                continue
            else:
                data.append([avp.code, avp.name])

        print >> sys.stdout, json.dumps(data)


def python_creator(app, msg, args):
    data = b"m = Msg(R=True, P=False, E=False, T=False,  code=%d, app_id=%d, avps=[\n" % (msg.code, app.id)
    for avp in list_avps(msg):
        if avp.M:
            out = b"# %s (datatype:%s) \n" % (avp.name, avp.datatype)
        else:
            # If the --rmopt is set, do not print optionnals avp
            if args.rmopt and not(avp.code in args.addavp):
                continue
            else:
                out = b"# OPTIONAL %s (datatype:%s) \n" % (avp.name, avp.datatype)
            if avp.datatype == "Enumerated":
                out += b"# Possible values:\n"
                for i in avp.val_to_desc:
                    out += b"# %d: %s \n" % (i, avp.val_to_desc[i])
        # Pythonic avps lines construction
        out += b"\t Avp(code=%d, " % avp.code
        if avp.M == True:
            out += b"M=%r, " %avp.M

        if avp.P == True:
            out += b"P=%r, " %avp.P
        if avp.V == True:
            out += b"vendor_id=%d, " % avp.vendor_id
        if avp.allows_stacking == True:
            out += b"avps=[], "
        
        if avp.datatype == "Enumerated":
            out += b"u32=), \n\n"
        else:
            out += b"data=''), \n\n"
        
        data += out
    data += b"])"
    return data


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
    parser.add_argument('--addavp',
    help='Add specific AVP to the output. Useful whith the --rmopt option.')

    parser.add_argument('-m', '--rmopt', default=False, action='store_true', 
    help='Mandatory Only. Remove the Optionnals Avps (default: false). Only useful in Creation mode ')



    args = parser.parse_args()

    if args.addavp is not None:
        args.addavp = list(int(x) for x in args.addavp.split(','))
    else:
        args.addavp= []

    # We can't be in both Creation Mode and Listing Mode at the same time
    assert(not(args.l and args.c))
    
    if args.l is None and args.c is None:
        print >> sys.stderr, "You must chose a mode. Either listing (-l) or creation (-c). See --help for usage informations."
        return -1
    # Listing Mode
    if args.l == True:
        #print("Listing Mode.")
        
        if args.app == None or args.app=="":
            
            print_app(args)

        else:
            app = get_application(args.app)
            assert(app)
            # We've got the App and we want to list potentials msgs
            if args.msg == None or args.msg=="":
                
                print_msg(app, args)

            else:
                msg = get_message(app, args.msg)
                assert(msg)
                # We've got both the APP and the MSG and we want to list the AVPs
                print_avp(app, msg, args)                
    else:
        #print ("Creation Mode")
        if args.app!=None and args.msg !=None and args.app!="" and args.msg!="":

            app = get_application(args.app)
            assert(app)
            msg = get_message(app, args.msg)
            assert(msg)
            
            data = python_creator(app, msg, args)

            print >> sys.stdout, data
        else:
            print >> sys.stderr, "In creative mode, both --app and --msg must be defined. See --help for usage informations."
            return -1
if __name__ == '__main__':
    main()
