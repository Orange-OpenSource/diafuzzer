#!/usr/bin/python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

from Dia import Application
import sys
import getopt

try:
  opts, args = getopt.getopt(sys.argv[1:], 'i', [])
except getopt.GetoptError as err:
  print >>sys.stderr, str(err)
  sys.exit(1)

rewrite_inplace = False

for (o, a) in opts:
  if o == '-i':
    rewrite_inplace = True

if len(args) < 1:
  print >>sys.stderr, 'usage: %s <dia dict>...'
  sys.exit(1)

for n in args:
  app = Application.load(n)
  app.verify()

  if rewrite_inplace:
    with open(n, 'wb') as f:
      f.write('%r' % app)
  else:
    print('%r' % app)

