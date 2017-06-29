#!/usr/bin/python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys
import socket as sk
import getopt
from threading import Thread
import select as sl
import os

import Diameter as dm
from scenario import load_scenario, dwr_handler

def usage(arg0):
  print('''usage: %s [--help] --scenario=<.scn file> --mode=<client|clientloop|server>
  --local-hostname=<sut.realm> --local-realm=<realm> <target:port>''' % arg0)
  sys.exit(1)

if __name__ == '__main__':
  scn = None
  mode = None
  local_hostname = None
  local_realm = None

  try:
    opts, args = getopt.getopt(sys.argv[1:], "hs:m:H:R:", ["help", "scenario=", "mode=", "local-hostname=",
      "local-realm="])
  except getopt.GetoptError as err:
    print(str(err))
    usage(sys.argv[1])
    sys.exit(2)

  for o, a in opts:
    if o in ('-h', '--help'):
      usage(sys.argv[0])
    if o in ('-s', '--scenario'):
      scn = a
    if o in ('-m', '--mode'):
      if a not in ['client', 'clientloop', 'server']:
        usage(sys.argv[0])
      mode = a
    if o in ('-H', '--local-hostname'):
      local_hostname = a
    if o in ('-R', '--local-realm'):
      local_realm = a

  if len(args) != 1 or local_hostname is None or local_realm is None \
    or scn is None or mode is None:
    usage(sys.argv[0])

  scenario = load_scenario(scn, local_hostname, local_realm)

  (host, port) = args[0].split(':')
  port = int(port)

  if mode == 'client' or mode == 'clientloop':
    while True:
      f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
      f.connect((host, port))

      (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm)
      if exc_info is not None:
        print('raised: %s' % (exc_info))
      f.close()

      if mode == 'client':
        break
  elif mode == 'server':
    srv = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    srv.bind((host, port))
    srv.listen(64)

    while True:
      (f,_) = srv.accept()
      (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm)
      if exc_info is not None:
        print('raised: %s' % (exc_info))
      f.close()
