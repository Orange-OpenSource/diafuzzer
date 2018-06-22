#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys
from getopt import getopt
from collections import OrderedDict

from Pdml import PdmlLoader
import Diameter as dm

from Dia import *
import os
from cPickle import load

if os.path.exists('.dia-cache'):
  with open('.dia-cache', 'rb') as f:
    d = load(f)
else:
  d = Directory()

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

def explode(m):
  values = {}

  def explode_avp(a, path):
    vendor = a.vendor
    if vendor is None:
      vendor = 0

    avps = d.find_avps(vendor, a.code)
    # need to handle AVP name ambiguity
    model_a = avps[0]
    (name, datatype) = (model_a.name, model_a.datatype)

    if hasattr(a, 'data') and len(a.data) > 4 and not a.avps:
      assert(path not in values)
      values[(path, name)] = a.data
      return

    paths = group_by_code(a.avps)
    for i in range(len(a.avps)):
      sub_a = a.avps[i]
      explode_avp(sub_a, path + '/' + get_path(sub_a, paths))

  paths = group_by_code(m.avps)
  for i in range(len(m.avps)):
    a = m.avps[i]
    explode_avp(a, '/' + get_path(a, paths))

  m.values = values

def lookup(msgs, val):
  for m in msgs:
    for k in m.values:
      if m.values[k] == val:
        return (m, k)

def usage(arg0):
  print('''usage: %s [--client=<generated client scenario>] [--server=<generated server scenario] <pcap file>''' % arg0)
  sys.exit(1)



if __name__ == '__main__':
  client_dump = None
  client_empty = True

  server_dump = None
  server_empty = True

  try:
    opts, args = getopt(sys.argv[1:], 'c:s:h', ['client=', 'server=', 'help'])
    for o, a in opts:
      if o in ('-c', '--client'):
        client_dump = open(a, 'wb')
        client_dump.write('def run(f, args={}):\n')
      elif o in ('-s', '--server'):
        server_dump = open(a, 'wb')
        server_dump.write('def run(f, args={}):\n')
      elif o in ('-h', '--help'):
        usage(sys.argv[0])
  except:
    sys.exit(2)

  if len(args) != 1:
    usage(sys.argv[0])

  if client_dump is None and server_dump is None:
    print >>sys.stderr, "As per your options, no scenario will be generated"


  pcap = args[0]

  c = PdmlLoader(pcap)

  if len(c.flows) == 0:
    print >>sys.stderr, 'Could not find a flow in capture %s' % pcap
    sys.exit(1)
  elif len(c.flows) > 1:
    print >>sys.stderr, 'Multiple flows in capture %s' % pcap
    for flow in c.flows:
      print >>sys.stderr, flow
    sys.exit(1)

  flow = c.flows.pop()
  print('detected a flow %s:%d -> %s:%d' % flow[1:])

  msgs = []
  tsxs = []

  for pdu in c.pdus:
    m = dm.Msg.decode(pdu.content, tag=True)
    if m.code == 280: continue

    attrs = ['ipprotocol', 'ipsrc', 'sport', 'ipdst', 'dport']
    m.frm_number = pdu.pdml.frm_number
    m.index = len(msgs)
    m.from_client = reduce(lambda x,y: x and y, [getattr(pdu, attrs[i]) == flow[i] for i in range(len(flow))])
    if m.from_client:
      m.direction = 'c2s'
    else:
      m.direction = 's2c'
    if not m.R:
      e2e_id = m.e2e_id
      h2h_id = m.h2h_id
      m.in_response_to = None

      for prev_m in msgs:
        if prev_m.R and prev_m.e2e_id == e2e_id and prev_m.h2h_id == h2h_id:
          m.in_response_to = prev_m
          prev_m.answered_by = m
          m.tsx_id = len(tsxs)
          prev_m.tsx_id = len(tsxs)
          tsxs.append((prev_m, m))
          break

      assert(m.in_response_to is not None)

    explode(m)

    m.anchors = {}

    for a in m.all_avps():
      v = a.data
      anchor = lookup(msgs, v)
      if anchor:
        (prev_m, prev_loc) = anchor
        if prev_loc not in prev_m.anchors:
          prev_m.anchors[prev_loc] = []
        prev_m.anchors[prev_loc].append((m.frm_number, m.from_client, a))

    msgs.append(m)

  for m in msgs:
    for loc in m.anchors:
      print('anchor %r, propagating to %r' % (loc, m.anchors[loc]))

  if client_dump:
    client_dump.write('  tsxs = [()]*%d\n' % len(tsxs))
  if server_dump:
    server_dump.write('  tsxs = [()]*%d\n' % len(tsxs))

  for m in msgs:
    if m.R:
      emitter = '''
  # frame %d
  m = %s
  m.send(f)
  tsxs[%d] = (m.e2e_id, m.h2h_id)
''' % (m.frm_number, m.__repr__(2, 2)[2:], m.tsx_id)
    else:
      emitter = '''
  # frame %d
  m = %s
  (m.e2e_id, m.h2h_id) = tsxs[%d]
  m.send(f)
''' % (m.frm_number, m.__repr__(2, 2)[2:], m.tsx_id)

    if m.R:
      receiver = '''
  # frame %d
  m = Msg.recv(f)
  assert(m.code == %d)
  assert(m.R)
  tsxs[%d] = (m.e2e_id, m.h2h_id)
''' % (m.frm_number, m.code, m.tsx_id)
    else:
      receiver = '''
  # frame %d
  m = Msg.recv(f)
  assert(m.code == %d)
  assert(not m.R)
  assert(tsxs[%d] == (m.e2e_id, m.h2h_id))
''' % (m.frm_number, m.code, m.tsx_id)

    if m.from_client:
      if client_dump:
        client_dump.write(emitter)
        client_empty = False
      if server_dump:
        server_dump.write(receiver)
        server_empty = False
        for loc in m.anchors:
          (path, name) = loc
          name = name.replace('-', '_')
          name = name.lower()
          
          copy_locations = [next_loc for (next_m, from_client, next_loc) in m.anchors[loc] if not from_client]
          if len(copy_locations) > 0:
            server_dump.write('  %s = m.eval_path(%r).data\n' % (name, path))
            for copy_loc in copy_locations:
              copy_loc.var = name
    else:
      if client_dump:
        client_dump.write(receiver)
        client_empty = False
        for loc in m.anchors:
          (path, name) = loc
          name = name.replace('-', '_')
          name = name.lower()

          copy_locations = [next_loc for (next_m, from_client, next_loc) in m.anchors[loc] if from_client]
          if len(copy_locations) > 0:
            client_dump.write('  %s = m.eval_path(%r).data\n' % (name, path))
            for copy_loc in copy_locations:
              copy_loc.var = name
      if server_dump:
        server_dump.write(emitter)
        server_empty = False

  if client_dump:
    client_dump.write('\n  f.close()\n')
    client_dump.close()
  if server_dump:
    server_dump.write('\n  f.close()\n')
    server_dump.close()
