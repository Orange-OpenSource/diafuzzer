#!/usr/bin/env python2

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys
from threading import Thread
import select as sl
import os
import argparse
import sctp
import socket as sk

import Diameter as dm
from scenario import load_scenario, dwr_handler

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('--ipv6',
    help='Use IPv6', action='store_true')
  parser.add_argument('--local-addresses',
    help='Local addresses that will the addresses used in SCTP multihoming',
    default=[])
  parser.add_argument('--local-port',
    help='Local SCTP port', default=0, type=int)
  parser.add_argument('--local-hostname',
    help='Local Diameter Host, used in DWA as Origin-Host, and may be used as local_hostname',
    default='diafuzzer.invalid')
  parser.add_argument('--local-realm',
    help='Local Diameter realm, used in DWA as Origin-Realm, and may be used as local_realm',
    default='invalid')
  parser.add_argument('mode', help='Role: client, clientloop or server. When using client or clientloop, an additional positional argument describing the target IP and port, colon separated, must be used. When using server, local address and port must be given using options',
    choices=('client', 'clientloop', 'server'))
  parser.add_argument('scenario', help='Python scenario to run')
  parser.add_argument('remote', nargs=argparse.REMAINDER, help='target_ip port')

  args = parser.parse_args(sys.argv[1:])

  family = sk.AF_INET
  if args.ipv6:
    family = sk.AF_INET6

  if args.local_addresses:
    args.local_addresses = args.local_addresses.split(',')
  else:
    if family == sk.AF_INET:
      ADDR_ANY = '0.0.0.0'
    else:
      ADDR_ANY = '::'

  # parse additional argument in client or clientloop modes
  target = None
  if args.mode in ('client', 'clientloop'):
    if len(args.remote) != 2 or len(args.remote[0]) == 0:
      parser.print_help()
      print >>sys.stderr, 'using client or clientloop modes require to specify target ip port'
      sys.exit(1)

    target = args.remote[0]
    port = int(args.remote[1])

  # load scenario
  scenario = load_scenario(args.scenario, args.local_hostname, args.local_realm)

  if args.mode in ('client', 'clientloop'):
    while True:
      f = sk.socket(family, sk.SOCK_STREAM, sk.IPPROTO_SCTP)
      if args.local_addresses:
        addrs = [(a, int(args.local_port)) for a in args.local_addresses]
        ret = sctp.bindx(f, addrs, family)
        assert(ret == 0)
      else:
        f.bind((ADDR_ANY, args.local_port))

      f.connect((target, port))

      (exc_info, msgs) = dwr_handler(scenario, f, args.local_hostname, args.local_realm)
      if exc_info is not None:
        print('raised: %s' % (exc_info))
      f.close()

      if args.mode == 'client':
        break
  elif args.mode == 'server':
    srv = sk.socket(family, sk.SOCK_STREAM, sk.IPPROTO_SCTP)
    if args.local_addresses:
      addrs = [(a, int(args.local_port)) for a in args.local_addresses]
      ret = sctp.bindx(srv, addrs, family)
      assert(ret == 0)
    else:
      srv.bind((ADDR_ANY, args.local_port))
    srv.listen(64)

    while True:
      (f,_) = srv.accept()
      (exc_info, msgs) = dwr_handler(scenario, f, args.local_hostname, args.local_realm)
      if exc_info is not None:
        print('raised: %s' % (exc_info))
      f.close()
