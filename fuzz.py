#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

from Pdml import PdmlLoader
import Diameter as dm
from Dia import Directory

import socket as sk
from getopt import getopt
from threading import Thread
import select as sl
import os
from struct import pack
from functools import partial
from collections import namedtuple, OrderedDict
import sys
from random import randint

MsgAnchor = namedtuple('MsgAnchor', 'index code is_request')

class FuzzScenario:
  def __init__(self, msg_anchor, description):
    assert(isinstance(msg_anchor, MsgAnchor))
    self.anchor = msg_anchor
    self.description = description

    self.processed_msgs = []
    self.f = None

    self.act = None

  def bind(self, f):
    assert(self.f is None)
    self.f = f
    assert(self.f is not None)

  def send(self, msg):
    '''to be called on locally generated wire messages.'''
    assert(self.f is not None)
    assert(isinstance(msg, dm.Msg))

    activate = (len(self.processed_msgs) == self.anchor.index)
    self.processed_msgs.append((msg.code, msg.R))

    if activate:
      assert(msg.code == self.anchor.code and msg.R == self.anchor.is_request)
      assert(self.act)
      self.act(self, msg)
    else:
      self.xmit(msg)

  def xmit(self, msg):
    '''perform transmit of msg, without alteration.'''
    assert(self.f is not None)
    assert(isinstance(msg, dm.Msg))
    msg.send(self.f)

  def omit_msg(self, msg):
    pass

  def stutter_msg(self, msg):
    self.xmit(msg)

    msg.e2e_id = randint(0, pow(2, 32)-1)
    msg.h2h_id = randint(0, pow(2, 32)-1)
    self.xmit(msg)

  def absent_variant(self, msg, path):
    assert(isinstance(msg, dm.Msg))
    msg.suppress_avps(path)
    self.xmit(msg)

  def overpresent_variant(self, msg, path, count):
    assert(isinstance(msg, dm.Msg))
    msg.overflow_avps(path, count)
    self.xmit(msg)

  def set_value(self, msg, path, value):
    msg.modify_value(path, value)
    self.xmit(msg)

  def __repr__(self):
    return 'anchored at %r: %s' % (self.anchor, self.description)

def group_by_code(avps):
  codes = {}
  for a in avps:
    key = (a.code, a.vendor)
    if key not in codes:
      codes[key] = []
    codes[key].append(a)
  return codes

def get_path(a, codes):
  attrs = {}

  attrs['code'] = a.code
  if a.vendor != 0:
    attrs['vendor'] = a.vendor

  path = ','.join(['%s=%d' % (x, attrs[x]) for x in attrs])
  key = (a.code, a.vendor)
  if len(codes[key]) != 1:
    path += '[%d]' % (codes[key].index(a))

  return path

def unfold_avps(m):
  nodes = OrderedDict()

  def explode_avp(a, path):
    vendor = a.vendor
    if vendor is None:
      vendor = 0

    ma = a.model_avp
    (name, datatype) = (ma.name, ma.datatype)

    assert(path not in nodes)
    nodes[path] = a

    if not a.avps:
      return

    paths = group_by_code(a.avps)
    for i in range(len(a.avps)):
      sub_a = a.avps[i]
      explode_avp(sub_a, path + '/' + get_path(sub_a, paths))

  paths = group_by_code(m.avps)
  for i in range(len(m.avps)):
    a = m.avps[i]
    explode_avp(a, '/' + get_path(a, paths))

  return nodes

def grouped_variants(avps):
  for a in avps:
    assert(a.qualified_avp)
    qa = a.qualified_avp
    yield (a, 0, 'absent')
    yield (a, 64, 'present 64 times')
    if qa.max:
      yield (a, qa.max+1, 'present more than max allowed')

def non_grouped_variants(a):
  assert(a.model_avp)
  ma = a.model_avp
  assert(ma.datatype != 'Grouped')

  if ma.datatype == 'Enumerated':
    mn = min(ma.val_to_desc.keys())
    mx = max(ma.val_to_desc.keys())

    data = pack('!i', mn-1)
    yield (data, 'Enumerated lower than allowed')

    data = pack('!i', mx+1)
    yield (data, 'Enumerated bigger than allowed')
  elif ma.datatype == 'UTF8String':
    for bad in ['\x80', '\xbf', '\x80'*128]:
      yield (bad, 'UTF8String continuations')

    for bad in ['\xc0 ']:
      yield (bad, 'UTF8String lonely start')

    for bad in ['\xfe', '\xff']:
      yield (bad, 'UTF8String impossible bytes')

    for bad in [ '\xc0\xaf']:
      yield (bad, 'UTF8String overlong')

    for bad in ['\xef\xbf\xbe', '\xef\xbf\xbf']:
      yield (bad, 'UTF8String non-characters in 16bits')

  yield ('', 'empty value')

  for length in [3, 128+64, 8192+64]:
    data = '\xfe' * length
    yield (data, 'Generic overflow with %d bytes' % length)

  for fmt in ['%n', '%-1$n', '%4096$n']:
    data = fmt * 1024
    yield (data, 'Generic overflow with format specifier %r' % fmt)

def analyze(seq):
  fuzzs = []
  sent = 0

  for i in range(len(seq)):
    (msg, is_sent) = seq[i]
    if is_sent:
      anchor = MsgAnchor(sent, msg.code, msg.R)

      '''
      # perform omit and stutter sequence fuzzing
      # do not skip first message sent :)
      # need to dig deeper
      if i != 0 or not is_sent:
        s = FuzzScenario(anchor, 'omit %d-th sent message' % sent)
        s.act = lambda this, m: this.omit_msg(m)
        fuzzs.append(s)

      s = FuzzScenario(anchor, 'stutter %d-th sent message' % sent)
      s.act = lambda this, m: this.stutter_msg(m)
      fuzzs.append(s)
      '''

      # perform global structure fuzzing per message
      avps = msg.avps
      paths = group_by_code(avps)
      for (a, count, description) in grouped_variants(avps):
        s = FuzzScenario(anchor, description)
        path = '/' + get_path(a, paths)
        if count == 0:
          s.act = lambda this, m, path=path: this.absent_variant(m, path)
        else:
          s.act = lambda this, m, path=path, count=count: this.overpresent_variant(m, path, count)
        fuzzs.append(s)

      # perform field level fuzzing, Grouped as well as non Grouped
      avps = unfold_avps(msg)
      for path in avps:
        a = avps[path]
        assert(a.model_avp)
        ma = a.model_avp
        if ma.datatype == 'Grouped':
          paths = group_by_code(a.avps)
          for (sub_a, count, description) in grouped_variants(a.avps):
            s = FuzzScenario(anchor, description)
            sub_path = get_path(sub_a, paths)
            sub_path = path + '/' + sub_path
            if count == 0:
              s.act = lambda this, m, sub_path=sub_path: this.absent_variant(m, sub_path)
            else:
              s.act = lambda this, m, sub_path=sub_path, count=count: this.overpresent_variant(m, sub_path, count)
            fuzzs.append(s)
          # if ma allows for stacking e.g. CCF ends with *AVP
          # then generate a deep stacked self embedded AVP :)
          if ma.allows_stacking():
            data = a.overflow_stacking()
            s = FuzzScenario(anchor, '%s self-stacked -> %d' % (ma.name, len(data)))
            s.act = lambda this, m, path=path, data=data: this.set_value(m, path, data)
            fuzzs.append(s)
        else:
          for (data, description) in non_grouped_variants(a):
            s = FuzzScenario(anchor, '%s %s' % (ma.name, description))
            s.act = lambda this, m, path=path, data=data: this.set_value(m, path, data)
            fuzzs.append(s)

      sent += 1

  return fuzzs

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

def dwr_handler(scenario, f):
  msgs = []

  (own_plug, fuzzed_plug) = sk.socketpair(sk.AF_UNIX, sk.SOCK_SEQPACKET)

  child = Thread(target=scenario, args=[fuzzed_plug])
  child.start()

  while True:
    (readable, _, _) = sl.select([own_plug, f], [], [])

    if own_plug in readable:
      b = own_plug.recv(dm.U24_MAX)
      if len(b) == 0:
        break
      m = dm.Msg.decode(b)
      msgs.append((m, True))
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
        msgs.append((m, False))
        own_plug.send(b)

  own_plug.close()
  exc_info = child.join()

  return (exc_info, msgs)

def fuzz_handler(scenario, f, fuzz):
  assert(isinstance(fuzz, FuzzScenario))

  msgs = []

  (own_plug, fuzzed_plug) = sk.socketpair(sk.AF_UNIX, sk.SOCK_SEQPACKET)

  fuzz.bind(f)

  child = WrappedThread(fuzzed_plug, target=scenario, args=[fuzzed_plug])
  child.start()

  while True:
    (readable, _, _) = sl.select([own_plug, f], [], [])

    if own_plug in readable:
      b = own_plug.recv(dm.U24_MAX)
      if len(b) == 0:
        break
      m = dm.Msg.decode(b)
      msgs.append((m, True))
      assert(isinstance(m, dm.Msg))
      fuzz.send(m)
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
        msgs.append((m, False))
        own_plug.send(b)

  own_plug.close()
  exc_info = child.join()

  return (exc_info, msgs)

def desc_exc(exc_info):
  if exc_info is None:
    return 'all right'
  else:
    return '%r' % exc_info

if __name__ == '__main__':
  if len(sys.argv) != 4:
    print >>sys.stderr, 'usage: %s <.scn> [client|server] <0.0.0.0:port>' % sys.argv[0]
    sys.exit(1)

  scn = sys.argv[1]
  scenario = load_scenario(scn)
  print('loaded scenario %s' % scn)

  mode = sys.argv[2]

  (host, port) = sys.argv[3].split(':')
  port = int(port)

  if mode == 'client':
    # run once in order to capture exchanged pdus
    f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    f.connect((host, port))
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
      f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
      f.connect((host, port))
      (exc_info, msgs) = fuzz_handler(scenario, f, fuzz)
      f.close()

      print('%s: %s' % (fuzz.description, desc_exc(exc_info)))
  elif mode == 'server':
    srv = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    srv.bind((host, port))
    srv.listen(64)

    (f,_) = srv.accept()
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
      (f,_) = srv.accept()
      (exc_info, msgs) = fuzz_handler(scenario, f, fuzz)
      f.close()

      print('%s: %s' % (fuzz.description, desc_exc(exc_info)))
