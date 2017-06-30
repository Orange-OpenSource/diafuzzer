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


import socket as sk
import getopt
from threading import Thread
import select as sl
import os
from struct import pack
from functools import partial
from collections import namedtuple, OrderedDict
import sys
from random import randint

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

def usage(arg0):
  print('''usage: %s [--help] --scenario=<.scn file> --mode=<client|server> 
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
    usage(sys.argv[0])
    sys.exit(2)

  for o, a in opts:
    if o in ('-h', '--help'):
      usage(sys.argv[0])
    if o in ('-s', '--scenario'):
      scn = a
    if o in ('-m', '--mode'):
      if a not in ['client', 'server']:
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

  if mode == 'client':
    # run once in order to capture exchanged pdus
    f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    f.connect((host, port))
    (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm)
    if exc_info is not None:
      print('scenario raised: %s' % exc_info)
    f.close()

    for (m, is_sent) in msgs:
      Directory.tag(m)

    fuzzs = analyze(msgs)
    print('generated %d scenarios of fuzzing' % len(fuzzs))

    for fuzz in fuzzs:
      f = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
      f.connect((host, port))
      (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm, fuzz)
      if exc_info is not None:
        print('scenario %s raised: %s' % (fuzz.description, exc_info))
      else:
        print('scenario %s ok' % fuzz.description)
      f.close()

  elif mode == 'server':
    srv = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
    srv.bind((host, port))
    srv.listen(64)

    (f,_) = srv.accept()
    (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm)
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
      (exc_info, msgs) = dwr_handler(scenario, f, local_hostname, local_realm, fuzz)
      if exc_info is not None:
        print('scenario %s raised: %s' % (fuzz.description, exc_info))
      else:
        print('scenario %s ok' % fuzz.description)
      f.close()
