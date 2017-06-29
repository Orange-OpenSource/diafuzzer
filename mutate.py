#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import Diameter as dm

from collections import namedtuple

MsgAnchor = namedtuple('MsgAnchor', 'index code is_request')

class MutateScenario:
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
    self.f.sendall(msg.encode())

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
