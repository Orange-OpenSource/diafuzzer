#!/usr/bin/python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys

from Pdml import PdmlLoader
import Diameter as dm
from Dia import Directory

import conform

def cprint(what, color):
  COLORS = {
    'white': '\033[0m',
    'blue': '\033[94m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'brown': '\033[91m',
    'red': '\033[31m',
  }

  ENDC = '\033[0m'

  assert(color in COLORS)
  sys.stdout.write(COLORS[color] + what + ENDC)
  sys.stdout.flush()

if __name__ == '__main__':
  for pcap in sys.argv[1:]:
    c = PdmlLoader(pcap)

    for pdu in c.pdus:
      m = dm.Msg.decode(pdu.content, tag=True)

      violations = conform.conform_avps(m.avps, m.model.avps)
      if violations:
        cprint('frame %d failed to conform: %r\n' % (pdu.pdml.frm_number, violations), 'red')
