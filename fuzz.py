#!/usr/bin/env python2

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

from Pdml import PdmlLoader
import Diameter as dm
from Dia import Directory
from mutate import MsgAnchor, MutateScenario
from scenario import unpack_frame, pack_frame, dwr_handler, load_scenario


import getopt
from threading import Thread
import select as sl
import os
from struct import pack
from functools import partial
from collections import namedtuple, OrderedDict
from random import randint
import argparse
import sctp
import socket as sk
import sys



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
        s = MutateScenario(anchor, 'omit %d-th sent message' % sent)
        s.act = lambda this, m: this.omit_msg(m)
        fuzzs.append(s)

      s = MutateScenario(anchor, 'stutter %d-th sent message' % sent)
      s.act = lambda this, m: this.stutter_msg(m)
      fuzzs.append(s)
      '''

      # perform global structure fuzzing per message
      avps = msg.avps
      paths = group_by_code(avps)
      for (a, count, description) in grouped_variants(avps):
        s = MutateScenario(anchor, description)
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
            s = MutateScenario(anchor, description)
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
            s = MutateScenario(anchor, '%s self-stacked -> %d' % (ma.name, len(data)))
            s.act = lambda this, m, path=path, data=data: this.set_value(m, path, data)
            fuzzs.append(s)
        else:
          for (data, description) in non_grouped_variants(a):
            s = MutateScenario(anchor, '%s %s' % (ma.name, description))
            s.act = lambda this, m, path=path, data=data: this.set_value(m, path, data)
            fuzzs.append(s)

      sent += 1

  return fuzzs


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('--local-addresses',
    help='Local IPv4 addresses that will the addresses used in SCTP multihoming',
    default=[])
  parser.add_argument('--local-port',
    help='Local SCTP port', default=0)
  parser.add_argument('--local-hostname',
    help='Local Diameter Host, used in DWA as Origin-Host, and may be used as local_hostname',
    default='diafuzzer.invalid')
  parser.add_argument('--local-realm',
    help='Local Diameter realm, used in DWA as Origin-Realm, and may be used as local_realm',
    default='invalid')
  parser.add_argument('mode', help='Role: client, clientloop or server. When using client or clientloop, an additional positional argument describing the target IP and port, colon separated, must be used. When using server, local address and port must be given using options',
    choices=('client', 'server'))
  parser.add_argument('scenario', help='Python scenario to run')
  parser.add_argument('remote', nargs=argparse.REMAINDER, help='Target IP:port')

  args = parser.parse_args(sys.argv[1:])

  if args.local_addresses:
    args.local_addresses = args.local_addresses.split(',')

  # parse additional argument in client or clientloop modes
  target = None
  if args.mode in ('client', 'clientloop'):
    if len(args.remote) != 1 or len(args.remote[0]) == 0:
      parser.print_help()
      print >>sys.stderr, 'using client or clientloop modes require to specify target IP:port'
      sys.exit(1)

    target = args.remote[0]
    (host, port) = target.split(':')
    port = int(port)


  # load scenario
  scenario = load_scenario(args.scenario, args.local_hostname, args.local_realm)


  if args.mode == 'client':
    # run once in order to capture exchanged pdus
    f = sk.socket(sk.AF_INET, sk.SOCK_STREAM, sk.IPPROTO_SCTP)
    if args.local_addresses:
      addrs = [(a, 0) for a in args.local_addresses]
      ret = sctp.bindx(f, addrs)
      assert(ret == 0)
    else:
      f.bind(('0.0.0.0', args.local_port))
    f.connect((host, port))

    (exc_info, msgs) = dwr_handler(scenario, f, args.local_hostname, args.local_realm)
    if exc_info is not None:
      print('scenario raised: %s' % exc_info)
    f.close()

    for (m, is_sent) in msgs:
      Directory.tag(m)

    fuzzs = analyze(msgs)
    print('generated %d scenarios of fuzzing' % len(fuzzs))

    for fuzz in fuzzs:
      f = sk.socket(sk.AF_INET, sk.SOCK_STREAM, sk.IPPROTO_SCTP)
      if args.local_addresses:
        addrs = [(a, 0) for a in args.local_addresses]
        ret = sctp.bindx(f, addrs)
        assert(ret == 0)
      else:
        f.bind(('0.0.0.0', args.local_port))
      f.connect((host, port))

      (exc_info, msgs) = dwr_handler(scenario, f, args.local_hostname, args.local_realm)
      if exc_info is not None:
        print('scenario %s raised: %s' % (fuzz.description, exc_info))
      else:
        print('scenario %s ok' % fuzz.description)
      f.close()

  elif args.mode == 'server':
    srv = sk.socket(sk.AF_INET, sk.SOCK_STREAM, sk.IPPROTO_SCTP)
    if args.local_addresses:
      addrs = [(a, int(args.local_port)) for a in args.local_addresses]
      ret = sctp.bindx(srv, addrs)
      assert(ret == 0)
    else:
      srv.bind(('0.0.0.0', args.local_port))
    srv.listen(64)

    (f,_) = srv.accept()
    (exc_info, msgs) = dwr_handler(scenario, f, args.local_hostname, args.local_realm)
    if exc_info is not None:
      print('scenario %s raised: %s' % (fuzz.description, exc_info))
    else:
      print('scenario %s ok' % fuzz.description)
    f.close()

    for (m, is_sent) in msgs:
      Directory.tag(m)

    fuzzs = analyze(msgs)
    print('generated %d scenarios of fuzzing' % len(fuzzs))

    for fuzz in fuzzs:
      (f,_) = srv.accept()
      (exc_info, msgs) = dwr_handler(scenario, f, args.local_hostname, args.local_realm, fuzz)
      if exc_info is not None:
        print('scenario %s raised: %s' % (fuzz.description, exc_info))
      else:
        print('scenario %s ok' % fuzz.description)
      f.close()
