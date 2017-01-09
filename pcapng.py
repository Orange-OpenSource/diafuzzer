#!/usr/bin/python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

from cStringIO import StringIO
from struct import pack, unpack
from collections import namedtuple
from contextlib import contextmanager

class ShortRead(Exception): pass
class InvalidValue(Exception): pass

U16FMT = 'H'
U32FMT = 'I'
I64FMT = 'q'
U64FMT = 'Q'

Block = namedtuple('Block', 'type body')
SHBlock = namedtuple('SHBlock', 'endianness minor major next_length options')
IDBlock = namedtuple('IDBlock', 'linktype snaplen opts')
EPBlock = namedtuple('EPBlock', 'iid ts caplen origlen frame opts')

def read_options(f, endianness):
  assert(endianness in ['<', '>'])

  while True:
    data = f.read(4)
    if len(data) != 4: raise ShortRead()

    (type, length) = unpack(endianness + 2*U16FMT, data)

    data = f.read(length)
    if len(data) != length: raise ShortRead()

    while length % 4 != 0:
      padding = f.read(1)
      assert(len(padding) == 1)
      length += 1

    if type == 0:
      assert(len(data) == 0)
      return

    yield (type, data)

def write_options(opts):
  out = StringIO()

  for (type, data) in opts:
    out.write(pack('!' + 2*U16FMT, type, len(data)))
    out.write(data)

    padlen = len(data)
    while padlen % 4 != 0:
      out.write('\x00')
      padlen += 1

  out.write(pack('!' + 2*U16FMT, 0, 0))

  return out.getvalue()

def read_shblock(f):
  data = f.read(12)
  if len(data) != 12: raise ShortRead()

  (type, length, bom) = unpack(3*U32FMT, data)
  if type != 0x0a0d0d0a: raise InvalidValue()
  if bom == 0x1a2b3c4d:
    endianness = '<'
  elif bom == 0x4d3c2b1a:
    endianness = '>'
  else: raise InvalidValue()

  (type, length, bom) = unpack(endianness + 3*U32FMT, data)
  assert(type == 0x0a0d0d0a)
  assert(bom == 0x1a2b3c4d)
  assert(length > 12)

  total_length = length
  length -= 12

  data = f.read(4)
  if len(data) != 4: raise ShortRead()
  length -= 4

  (minor, major) = unpack(endianness + 2*U16FMT, data)

  data = f.read(8)
  if len(data) != 8: raise ShortRead()
  length -= 8

  (next_length,) = unpack(endianness + I64FMT, data)

  assert(length >= 4)
  opts = []
  if length > 4:
    data = f.read(length - 4)
    if len(data) != length-4: raise ShortRead()
    length = 4

    # parse options in data
    subf = StringIO(data)
    for type, data in read_options(subf, endianness):
      opts.append((type, data))

  data = f.read(4)
  if len(data) != 4: raise ShortRead()
  length -= 4

  (same_length,) = unpack(endianness + U32FMT, data)
  assert(same_length == total_length)

  return SHBlock(endianness, minor, major, next_length, opts)

def write_shblock(f):
  opts = write_options([(4, 'pypcapng')])

  f.write(pack('!' + 3*U32FMT, 0x0a0d0d0a, len(opts)+28, 0x1a2b3c4d))
  f.write(pack('!' + 2*U16FMT, 1, 0))
  f.write(pack('!' + I64FMT, -1))
  f.write(opts)
  f.write(pack('!' + U32FMT, len(opts)+28))

def read_block(f, endianness):
  data = f.read(8)
  if len(data) == 0: return
  elif len(data) != 8: raise ShortRead()

  (type, length) = unpack(endianness + 2*U32FMT, data)

  body = f.read(length-12)
  if len(body) != length-12: raise ShortRead()

  data = f.read(4)
  if len(data) != 4: raise ShortRead()
  (same_length,) = unpack(endianness + U32FMT, data)

  if same_length != length: raise InvalidValue()

  if type == 1:
    (linktype, reserved, snaplen) = unpack(endianness + 2*U16FMT + U32FMT,
      body[:8])
    body = body[8:]

    opts = []
    if body:
      subf = StringIO(body)
      for type, data in read_options(subf, endianness):
        opts.append((type, data))

    return IDBlock(linktype, snaplen, opts)
  elif type == 6:
    (iid, ts, caplen, origlen) = unpack(endianness + U32FMT + U64FMT + 2*U32FMT,
      body[:20])
    body = body[20:]

    frame = body[:caplen]
    body = body[caplen:]
    padlen = caplen
    while padlen % 4 != 0:
      body = body[1:]
      padlen += 1

    opts = []
    if body:
      subf = StringIO(body)
      for type, data in read_options(subf, endianness):
        opts.append((type, data))

    return EPBlock(iid, ts, caplen, origlen, frame, opts)
  else:
    return Block(type, body)

def write_block(f, type, body):
  f.write(pack('!' + 2*U32FMT, type, len(body)+12))
  f.write(body)
  f.write(pack('!' + U32FMT, len(body)+12))

def write_idblock(f):
  body = pack('!' + 2*U16FMT + U32FMT, 147, 0, (1<<32)-1)
  write_block(f, 1, body)

def write_epblock(f, ts, frame, comment=None, direction=None):
  body = StringIO()

  body.write(pack('!' + U32FMT + U64FMT + 2*U32FMT, 0, ts, len(frame), len(frame)))
  body.write(frame)

  padlen = len(frame)
  while padlen % 4 != 0:
    body.write('\x00')
    padlen += 1

  opts = []
  if comment:
    opts.append((1, comment))
  if direction:
    assert(direction in ['inbound', 'outbound'])
    if direction == 'inbound':
      value = 0b01
    if direction == 'outbound':
      value = 0b10
    opts.append((2, pack('!I', value)))

  if len(opts) > 0:
    body.write(write_options(opts))

  write_block(f, 6, body.getvalue())

