#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys

from Pdml import PdmlLoader
from Diameter import Msg
from cStringIO import StringIO

if __name__ == '__main__':
  pcap = sys.argv[1]

  c = PdmlLoader(pcap)

  for pdu in c.pdus:
    m = Msg.decode(pdu.content)

    print('''# frame %d
%r
''' % (pdu.pdml.frm_number, m))
