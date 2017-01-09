#!/usr/bin/python

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

local_host = 'hss.invalid.tld'
local_realm = 'hss.mnc999.mcc999.3gppnetwork.org'

def load_scenario(scn):
  globs = globals()
  globs['Msg'] = dm.Msg
  globs['Avp'] = dm.Avp
  globs['RecvMismatch'] = dm.RecvMismatch

  execfile(scn, globs, globs)

  assert('run' in globs)

  return globs['run']

class WrappedThread(Thread):
  def __init__(self, plug, **kwargs):
    super(WrappedThread, self).__init__(**kwargs)
    self.real_run = self.run
    self.run = self.wrapped_run
    self.exc_info = None
    self.plug = plug

  def wrapped_run(self):
    try:
      self.real_run()
    except:
      e = sys.exc_info()[0]
      self.exc_info = e
    finally:
      self.plug.close()

  def join(self):
    Thread.join(self)
    return self.exc_info

def dwr_handler(fuzzed, f):
  (own_plug, fuzzed_plug) = sk.socketpair(sk.AF_UNIX, sk.SOCK_SEQPACKET)

  child = WrappedThread(fuzzed_plug, target=fuzzed, args=[fuzzed_plug])
  child.start()

  while True:
    (readable, _, _) = sl.select([own_plug, f], [], [])

    if own_plug in readable:
      try:
        b = own_plug.recv(dm.U24_MAX)
        if len(b) == 0:
          break
      except:
        break
      f.send(b)
    elif f in readable:
      b = f.recv(dm.U24_MAX)
      if len(b) == 0:
        break

      m = dm.Msg.decode(b)
      if m.code == 280 and m.R:
        dwa = dm.Msg(code=280, R=False, e2e_id=m.e2e_id, h2h_id=m.h2h_id, avps=[
          dm.Avp(code=264, M=True, data=local_host),
          dm.Avp(code=296, M=True, data=local_realm),
          dm.Avp(code=268, M=True, u32=2001),
          dm.Avp(code=278, M=True, u32=0xcafebabe)])
        f.send(dwa.encode())
      else:
        own_plug.send(b)

  own_plug.close()
  return child.join()

if __name__ == '__main__':
  if len(sys.argv) != 4:
    print >>sys.stderr, 'usage: %s <.scn> [client|clientloop|server] <0.0.0.0:port>' % sys.argv[0]
    sys.exit(1)

  scn = sys.argv[1]
  scenario = load_scenario(scn)

  mode = sys.argv[2]

  (host, port) = sys.argv[3].split(':')
  port = int(port)

  if mode == 'client' or mode == 'clientloop':
    while True:
      f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
      f.connect((host, port))

      exc_info = dwr_handler(scenario, f)
      if mode == 'client':
        if exc_info is None:
          print('all good')
        else:
          print('*** %r' % exc_info)

      f.close()

      if mode == 'client':
        break
  elif mode == 'server':
    srv = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    srv.bind((host, port))
    srv.listen(64)

    while True:
      (f,_) = srv.accept()
      child = Thread(target=dwr_handler, args=[scenario, f])
      child.start()
