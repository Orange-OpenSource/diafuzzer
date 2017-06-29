#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import Diameter as dm

from struct import pack, unpack
from threading import Thread
from mutate import MsgAnchor, MutateScenario

import socket as sk
import select as sl
import sys
import traceback

class Disconnected(Exception): pass
class FramingError(Exception): pass

def unpack_frame(f):
  data = f.recv(4)
  if len(data) == 0: raise Disconnected()
  if len(data) != 4: raise FramingError(len(data), 4)

  (length,) = unpack('!I', data)

  data = ''
  while len(data) < length:
    appended = f.recv(length-len(data))
    if len(appended) == 0:
      raise Disconnected()

    data += appended

  if len(data) != length: raise FramingError(len(data), length)

  return data

def pack_frame(f, data):
  length = pack('!I', len(data))

  f.sendall(length + data)

def load_scenario(scn, local_hostname, local_realm):
  globs = globals()

  globs['Msg'] = dm.Msg
  globs['Avp'] = dm.Avp
  globs['RecvMismatch'] = dm.RecvMismatch
  globs['local_hostname'] = local_hostname
  globs['local_realm'] = local_realm

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
      self.exc_info = traceback.format_exc()
    finally:
      self.plug.close()

  def join(self):
    Thread.join(self)
    return self.exc_info

def dwr_handler(scenario, f, local_host, local_realm, mutator=None):
  assert(mutator is None or isinstance(mutator, MutateScenario))

  break_reason = None
  msgs = []

  (own_plug, fuzzed_plug) = sk.socketpair(sk.AF_UNIX, sk.SOCK_STREAM)

  if mutator is not None:
    mutator.bind(f)

  child = WrappedThread(fuzzed_plug, target=scenario, args=[fuzzed_plug])
  child.start()

  while True:
    (readable, _, _) = sl.select([own_plug, f], [], [])

    if own_plug in readable:
      try:
        b = unpack_frame(own_plug)
        m = dm.Msg.decode(b)
        msgs.append((m, True))
        assert(isinstance(m, dm.Msg))
      except Disconnected as e:
        break
      except Exception as e:
        break_reason = traceback.format_exc()
        break

      if mutator:
        mutator.send(m)
      else:
        f.sendall(b)

    elif f in readable:
      try:
        b = f.recv(dm.U24_MAX)
        if len(b) == 0:
          break
      except Exception as e:
        break_reason = traceback.format_exc()
        break

      m = dm.Msg.decode(b)
      if m.code == 280 and m.R:
        dwa = dm.Msg(code=280, R=False, e2e_id=m.e2e_id, h2h_id=m.h2h_id, avps=[
          dm.Avp(code=264, M=True, data=local_host),
          dm.Avp(code=296, M=True, data=local_realm),
          dm.Avp(code=268, M=True, u32=2001),
          dm.Avp(code=278, M=True, u32=0xcafebabe)])
        f.sendall(dwa.encode())
      else:
        msgs.append((m, False))
        pack_frame(own_plug, b)

  own_plug.close()
  exc_info = child.join()

  if not exc_info:
    exc_info = break_reason

  return (exc_info, msgs)
