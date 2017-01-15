#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import requests
import zipfile
from itertools import count
from cStringIO import StringIO
import sys

def num2b36(n):
  assert(n >= 0 and n < 36)
  if n < 10:
    return '%d' % n
  elif n < 36:
    return chr(ord('a')+n-10)

def generate_url(ts, major, minor, patch, serie=None):
  if serie is None:
    serie = ts.split('.')[0]

  major = num2b36(major)
  minor = num2b36(minor)
  patch = num2b36(patch)

  ts_nodot = ''.join(ts.split('.'))

  return 'http://www.3gpp.org/ftp/Specs/archive/%s_series/%s/%s-%s%s%s.zip' % (
    serie, ts, ts_nodot,
    major, minor, patch)

class UnknownResource(Exception): pass

def fetch(url):
  r = requests.get(url)
  return (r.status_code, r.content)

def generate_patches(ts, major, minor, serie=None):
  for p in count(0):
    yield generate_url(ts, major, minor, p, serie)

def peel_zip(content):
  f = StringIO(content)
  z = zipfile.ZipFile(f, 'r')
  z.extractall()

if len(sys.argv) < 2:
  print('usage: %s 29.272 <3gpp specs...>' % sys.argv[0])
  sys.exit(1)

for spec in sys.argv[1:]:
  for major in range(8, 15):
    for minor in count(0):
      retrieved_for_minor = 0
      for url in generate_patches(spec, major, minor):
        (status_code, content) = fetch(url)
        if status_code == 404:
          break
        else:
          peel_zip(content)
          retrieved_for_minor += 1
      if retrieved_for_minor == 0:
        break
    print('  processed release %d' % major)
