#!/usr/bin/python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys

import Diameter as dm
from Pdml import PdmlLoader

from Dia import Directory

from struct import unpack, pack
import random
from fuzz import fuzz_msg

import pcapng

if __name__ == '__main__':
  random.seed(0)

  if len(sys.argv) != 2:
    print >>sys.stderr, 'usage: %s <.pcap>' % sys.argv[0]
    sys.exit(1)

  f = sys.stdout

  pcapng.write_shblock(f)
  pcapng.write_idblock(f)

  pcap = sys.argv[1]
  c = PdmlLoader(pcap)
  for pdu in c.pdus:
    m = dm.Msg.decode(pdu.content)
    Directory.tag(m)

    pcapng.write_epblock(f, 0, m.encode(), 'No fuzzing', 'inbound')

    for mutated, comment in fuzz_msg(m):
      mutated.e2e_id = None
      mutated.h2h_id = None

      raw = mutated.encode()
      pcapng.write_epblock(f, 0, raw, comment, 'inbound')

  f.flush()
  f.close()
