#!/usr/bin/python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

from struct import pack, unpack
from cStringIO import StringIO
import time
import re
from pprint import pformat
from Dia import Directory
from random import randint
from copy import deepcopy
import sys

class IncompleteBuffer(Exception): pass
class MsgInvalidLength(Exception): pass
class AVPInvalidLength(Exception): pass

'''can be triggered at runtime by script'''
class RecvMismatch(Exception): pass

U16_MAX = pow(2,16)-1
U24_MAX = pow(2,24)-1

def pack24(x):
  assert(x >= 0 and x <= U24_MAX)
  s = pack('!L', x)
  return s[1:]

def unpack24(x):
  xp = '\x00' + x
  return unpack('!L', xp)[0]

assert(pack24(0) == '\x00\x00\x00')
assert(0 == unpack24('\x00\x00\x00'))

def read_exactly(f, n):
  b = f.read(n)
  if len(b) != n: raise IncompleteBuffer()
  return b

def get_matcher(elm):
  m = re.match(r'code=(\d+)(?:,vendor=(\d+))?(?:\[(\d+)\])?', elm)
  assert(m)

  (code, vendor, index) = m.groups()

  if index is None:
    index = 0
  else:
    index = int(index, 0)

  if vendor is None:
    vendor = 0
  else:
    vendor = int(vendor, 0)

  code = int(code, 0)

  return lambda x, code=code, vendor=vendor: x.code == code and x.vendor == vendor

def get_filter(elm):
  m = re.match(r'code=(\d+)(?:,vendor=(\d+))?(?:\[(\d+)\])?', elm)
  assert(m)

  (code, vendor, index) = m.groups()

  if index is None:
    index = 0
  else:
    index = int(index, 0)

  if vendor is None:
    vendor = 0
  else:
    vendor = int(vendor, 0)

  code = int(code, 0)

  def find_it(elms):
    avps = [e for e in elms if e.code == code and e.vendor == vendor]
    return avps[index]

  return find_it

sys.setrecursionlimit(10000)

class Msg:
  def __init__(self, **kwds):
    self.version = 1
    self.length = None
    self.R = False
    self.P = False
    self.E = False
    self.T = False
    self.reserved = None
    self.code = 0
    self.app_id = 0
    self.e2e_id = None
    self.h2h_id = None
    self.avps = []

    for k in kwds:
      setattr(self, k, kwds[k])

  def __repr__(self, offset=0, indent=2):
    attrs = {}

    for k in ['code', 'app_id', 'e2e_id', 'h2h_id', 'avps']:
      attrs[k] = getattr(self, k)

    if self.R: attrs['R'] = True
    if self.P: attrs['P'] = True
    if self.E: attrs['E'] = True
    if self.T: attrs['T'] = True
    if self.version != 1: attrs['version'] = self.version
    if self.length is not None: attrs['length'] = self.length

    r = ' '*offset + 'Msg('
    elms = []
    for k in ['version', 'R', 'P', 'E', 'T', 'reserved',
      'code', 'app_id']:
      if k in attrs:
        if k == 'app_id':
          elms.append('%s=0x%x' % (k, attrs[k]))
        else:
          elms.append('%s=%r' % (k, attrs[k]))
    r += ', '.join(elms)
    if 'avps' in attrs:
      r += ', avps=[\n'
      for a in self.avps:
        r += a.__repr__(offset+indent, indent) + ',\n'
      r += ' '*offset + ']'
    r += ')'

    return r

  @staticmethod
  def recv(f, _timeout=-1):
    if _timeout == -1:
      _timemout = 5

    f.settimeout(_timeout)
    data = f.recv(U24_MAX)
    return Msg.decode(data)

  def send(self, f):
    data = self.encode()
    f.send(data)

  @staticmethod
  def decode(s, tag=False):
    f = StringIO(s)

    attrs = {}

    attrs['version'] = unpack('!B', read_exactly(f, 1))[0]
    attrs['total_length'] = unpack24(read_exactly(f, 3))

    flags = unpack('!B', read_exactly(f, 1))[0]
    if flags & 0x80: attrs['R'] = True
    if flags & 0x40: attrs['P'] = True
    if flags & 0x20: attrs['E'] = True
    if flags & 0x10: attrs['T'] = True
    reserved = flags & 0x0f
    if reserved: attrs['reserved'] = reserved

    attrs['code'] = unpack24(read_exactly(f, 3))

    attrs['app_id'] = unpack('!L', read_exactly(f, 4))[0]
    attrs['h2h_id'] = unpack('!L', read_exactly(f, 4))[0]
    attrs['e2e_id'] = unpack('!L', read_exactly(f, 4))[0]

    length = attrs['total_length']
    length -= 20
    if length < 0: raise MsgInvalidLength()

    avps = []

    data = read_exactly(f, length)

    while True:
      a = Avp.decode(data)
      avps.append(a)

      assert(a.padded_length % 4 == 0)
      data = data[a.padded_length:]

      if len(data) == 0:
        break

    attrs['avps'] = avps

    m = Msg(**attrs)
    if tag:
      Directory.tag(m)
    return m

  def encode(self):
    f = StringIO()

    content = ''
    for a in self.avps:
      content += a.encode()

    if self.length:
      length = self.length
    else:
      length = len(content) + 20

    f.write(pack('!B', self.version))
    f.write(pack24(length))

    flags = 0
    if self.R: flags |= 0x80
    if self.P: flags |= 0x40
    if self.E: flags |= 0x20
    if self.T: flags |= 0x10
    if self.reserved: flags |= self.reserved

    f.write(pack('!B', flags))
    f.write(pack24(self.code))

    f.write(pack('!L', self.app_id))

    if self.h2h_id is None:
      self.h2h_id = randint(0, pow(2, 32)-1)
    f.write(pack('!L', self.h2h_id))

    if self.e2e_id is None:
      self.e2e_id = randint(0, pow(2, 32)-1)
    f.write(pack('!L', self.e2e_id))

    f.write(content)

    return f.getvalue()

  def all_avps(self):
    for a in self.avps:
      for sub_a in a.all_avps():
        yield sub_a

  def eval_path(self, path):
    elms = path.split('/')[1:]
    a = get_filter(elms[0])(self.avps)
    return a.eval_path(elms[1:])

  def modify_value(self, path, value):
    '''traverse AVP tree down to target, and set intermediate length to None
       in order to force fixup.'''
    elms = path.split('/')[1:]
    a = get_filter(elms[0])(self.avps)
    a.length = None
    a.modify_value(elms[1:], value)

  def suppress_avps(self, path):
    elms = path.split('/')[1:]
    assert(len(elms) >= 1)

    if len(elms) == 1:
      self.length = None
      m = get_matcher(elms[0])
      new_avps = []
      for a in self.avps:
        if not m(a):
          new_avps.append(a)
      self.avps = new_avps
    else:
      a = get_filter(elms[0])(self.avps)
      a.length = None
      a.suppress_avps(elms[1:])

  def overflow_avps(self, path, count):
    elms = path.split('/')[1:]
    assert(len(elms) >= 1)

    if len(elms) == 1:
      self.length = None
      m = get_matcher(elms[0])
      existing_avps = [a for a in self.avps if m(a)]
      existing_count = len(existing_avps)
      assert(existing_count > 0)
      self.avps.extend([existing_avps[-1]] * (count-existing_count))
    else:
      a = get_filter(elms[0])(self.avps)
      a.length = None
      a.overflow_avps(elms[1:], count)

  def compute_path(self, avp):
    avps = [a for a in self.avps if a.code == avp.code and a.vendor == avp.vendor]

    assert(len(avps) > 0)

    attrs = {}
    if avp.code != 0:
      attrs['code'] = avp.code
    if avp.vendor != 0:
      attrs['vendor'] = avp.vendor

    path = '/'
    for name in attrs:
      path += '%s=%d' % (name, attrs[name])

    if len(avps) == 1:
      return path
    else:
      return '%s[%d]' % (path, avps.index(avp))

class Avp:
  def __init__(self, **kwds):
    self.code = 0
    self.V = False
    self.M = False
    self.P = False
    self.reserved = None
    self.vendor = 0
    self.avps = []
    self.data = None
    self.length = None
    self.model = None

    for k in kwds:
      if k == 'u32':
        self.data = pack('!L', kwds[k])
      elif k == 's32':
        self.data = pack('!I', kwds[k])
      elif k == 'u64':
        self.data = pack('!Q', kwds[k])
      elif k == 'f32':
        self.data = pack('!f', kwds[k])
      elif k == 'f64':
        self.data = pack('!d', kwds[k])
      else:
        setattr(self, k, kwds[k])

  def __repr__(self, offset=0, indent=2):
    attrs = {}

    attrs['code'] = self.code

    for k in ['reserved', 'vendor', 'data', 'length']:
      if getattr(self, k) is not None:
        attrs[k] = getattr(self, k)

    if self.V: attrs['V'] = True
    if self.M: attrs['M'] = True
    if self.P: attrs['P'] = True
    if len(self.avps) > 0: attrs['avps'] = self.avps

    r = ' '*offset + 'Avp('
    elms = []

    for k in ['code', 'V', 'M', 'P', 'reserved', 'vendor']:
      if k in attrs:
        elms.append('%s=%r' % (k, attrs[k]))
    r += ', '.join(elms)

    if hasattr(self, 'var'):
      r += ', data=%s' % getattr(self, 'var')
    elif 'avps' in attrs:
      r += ', avps=[\n'
      for a in self.avps:
        r += a.__repr__(offset+indent, indent) + ',\n'
      r += ' '*offset + ']'
    elif 'data' in attrs:
      r += ', data=%r' % attrs['data']

    if self.model:
      r += ', conformant=%r' % self.model
 
    r += ')'
    return r

  def __eq__(self, other):
    if isinstance(other, self.__class__):
      return self.__dict__ == other.__dict__
    else:
      return False

  def __ne__(self, other):
    return not self.__eq__(other)

  @staticmethod
  def decode(s):
    f = StringIO(s)

    attrs = {}

    attrs['code'] = unpack('!L', read_exactly(f, 4))[0]

    flags = unpack('!B', read_exactly(f, 1))[0]
    if flags & 0x80: attrs['V'] = True
    if flags & 0x40: attrs['M'] = True
    if flags & 0x20: attrs['P'] = True
    reserved = flags & 0x1f
    if reserved: attrs['reserved'] = reserved

    length = unpack24(read_exactly(f, 3))
    attrs['length'] = length

    data_length = length
    data_length -= 8

    if flags & 0x80 != 0:
      attrs['vendor'] = unpack('!L', read_exactly(f, 4))[0]
      data_length -= 4

    if data_length < 0: raise AVPInvalidLength()

    data = read_exactly(f, data_length)
    attrs['padded_length'] = length
    if data_length % 4 != 0:
      padding = 4 - (data_length % 4)
      read_exactly(f, padding)
      attrs['padded_length'] += padding

    attrs['data'] = data

    if len(data) < 12:
      return Avp(**attrs)

    try:
      avps = []
      while True:
        cld_a = Avp.decode(data)
        avps.append(cld_a)

        assert(cld_a.padded_length % 4 == 0)
        data = data[cld_a.padded_length:]

        if len(data) == 0:
          break

      attrs['avps'] = avps
    except:
      pass

    return Avp(**attrs)

  def encode(self):
    f = StringIO()

    f.write(pack('!L', self.code))

    flags = 0
    if self.V: flags |= 0x80
    if self.M: flags |= 0x40
    if self.P: flags |= 0x20
    if self.reserved: flags |= self.reserved
    f.write(pack('!B', flags))

    content = ''
    if self.avps:
      content = ''
      for a in self.avps:
        content += a.encode()
    elif self.data:
      content = self.data

    length = self.length
    if length is None:
      length = len(content)
      length += 8
      if self.V:
        length += 4

    f.write(pack24(length))

    if self.V:
      f.write(pack('!L', self.vendor))

    if content:
      f.write(content)

    if length % 4 != 0:
      padding = 4 - (length % 4)
      f.write('\x00' * padding)

    return f.getvalue()

  def all_avps(self):
    yield self
    for a in self.avps:
      for sub_a in a.all_avps():
        yield sub_a

  def eval_path(self, elms):
    if len(elms) == 0:
      return self

    a = get_filter(elms[0])(self.avps)

    return a.eval_path(elms[1:])

  def modify_value(self, elms, value):
    '''traverse AVP tree down to target, and set intermediate length to None
       in order to force fixup.'''
    if len(elms) == 0:
      self.length = None
      self.data = value
      self.avps = []
      return

    a = get_filter(elms[0])(self.avps)
    a.length = None
    a.modify_value(elms[1:], value)

  def suppress_avps(self, elms):
    if len(elms) == 1:
      self.length = None
      m = get_matcher(elms[0])
      new_avps = []
      for a in self.avps:
        if not m(a):
          new_avps.append(a)
      self.avps = new_avps
    else:
      a = get_filter(elms[0])(self.avps)
      a.length = None
      a.suppress_avps(elms[1:])

  def overflow_avps(self, elms, count):
    if len(elms) == 1:
      self.length = None
      m = get_matcher(elms[0])
      existing_avps = [a for a in self.avps if m(a)]
      existing_count = len(existing_avps)
      assert(existing_count > 0)
      self.avps.extend([existing_avps[-1]] * (count-existing_count))
    else:
      a = get_filter(elms[0])(self.avps)
      a.length = None
      a.overflow_avps(elms[1:], count)

  def compute_path(self, avp):
    index = None
    total = 0
    found = False

    for a in self.avps:
      if a.code == avp.code and a.vendor == avp.vendor:
        seen += 1
      if a == avp:
        assert(index is None)
        index = seen-1

    assert(index is not None and seen >= 1)
    if seen == 1:
      return '/code=%d,vendor=%d' % (avp.code, avp.vendor)
    else:
      return '/code=%d,vendor=%d[%d]' % (avp.code, avp.vendor, seen-1)

  def overflow_stacking(self, depth=128):
    new_avp = deepcopy(self)

    for x in range(depth):
      stack_avp = deepcopy(self)
      stack_avp.length = None
      stack_avp.avps.append(new_avp)
      new_avp = stack_avp

    data = ''
    for a in self.avps:
      data += a.encode()
    data += new_avp.encode()

    return data

if __name__ == '__main__':
  from binascii import unhexlify as ux

  UNPADDED_AVP = ux('0000012b4000000c00000000')
  a = Avp.decode(UNPADDED_AVP)
  assert(a.encode() == UNPADDED_AVP)

  PADDED_AVP = ux('0000010d400000334d75205365727669636520416e616c797a6572204469616d6574657220496d706c656d656e746174696f6e00')
  a = Avp.decode(PADDED_AVP)
  assert(a.encode() == PADDED_AVP)

  CER = ux('010000c88000010100000000000000000000000000000108400000113132372e302e302e3100000000000128400000166473742e646f6d61696e2e636f6d0000000001014000000e00017f00000100000000010a4000000c000000000000010d400000334d75205365727669636520416e616c797a6572204469616d6574657220496d706c656d656e746174696f6e000000012b4000000c000000000000010c4000000c000007d100000104400000200000010a4000000c000028af000001024000000c01000000')
  m = Msg.decode(CER)
  assert(m.encode() == CER)

  m = Msg(avps=[Avp(code=280, data='toto'), Avp(code=280, data='toto'), Avp(code=280, data='tata')])
  p = m.compute_path(Avp(code=280, data='toto'))
  assert(p == '/code=280[0]')
  p = m.compute_path(Avp(code=280, data='tata'))
  assert(p == '/code=280[2]')

  m = Msg(avps=[Avp(code=280, data='toto'), Avp(code=281, data='toto'), Avp(code=282, data='tata')])
  p = m.compute_path(Avp(code=280, data='toto'))
  assert(p == '/code=280')

  m = Msg(avps=[Avp(code=280, data='toto'), Avp(code=281, data='toto'), Avp(code=282, data='tata')])
  p = m.compute_path(Avp(code=280, data='toto'))
  assert(p == '/code=280')

  m = Msg(avps=[Avp(code=280, data='toto'), Avp(code=280, data='toto'), Avp(code=280, data='tata')])
  a = m.eval_path('/code=280')
  assert(a == Avp(code=280, data='toto'))
  a = m.eval_path('/code=280[1]')
  assert(a == Avp(code=280, data='toto'))
  a = m.eval_path('/code=280,vendor=0[1]')
  assert(a == Avp(code=280, data='toto'))
  a = m.eval_path('/code=280[2]')
  assert(a == Avp(code=280, data='tata'))
