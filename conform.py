#!/usr/bin/python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

from Dia import *
from cPickle import load
from collections import namedtuple
from struct import unpack

QualifierViolation = namedtuple('QualifierViolation', 'qualified_avp avps')

def conform_avps(wire_avps, model_qavps):
  '''conform an array of AVPs against an array of qualified AVPs.'''

  violations = []

  for qa in model_qavps:
    avps = [a for a in wire_avps if a.qualified_avp == qa]
    cnt = len(avps)
    if not qa.accept(cnt):
      violations.append(QualifierViolation(qa, avps))

  for a in wire_avps:
    violations.extend(conform_avp(a))

  return violations

ExpectedLengthViolation = namedtuple('ExpectedLengthViolation', 'name avp expected')
UnknownEnumeratedViolation = namedtuple('UnknownEnumeratedViolation', 'name avp known')
UTF8Violation = namedtuple('UTF8Violation', 'name avp')

def conform_avp(a):
  '''conform an AVP value against its model AVP.'''

  violations = []

  if a.model_avp:
    if a.model_avp.datatype in Avp.KNOWN_LENGTH_DATATYPES:
      if len(a.data) not in Avp.KNOWN_LENGTH_DATATYPES[a.model_avp.datatype]:
        violations.append(ExpectedLengthViolation(a.model_avp.name, a,
          Avp.KNOWN_LENGTH_DATATYPES[a.model_avp.datatype]))
        return violations

    if a.model_avp.datatype == 'Grouped':
      violations.extend(conform_avps(a.avps, a.model_avp.grouped))
    elif a.model_avp.datatype == 'Enumerated':
      u32 = unpack('!L', a.data)[0]
      if u32 not in a.model_avp.val_to_desc:
        violations.append(UnknownEnumeratedViolation(a.model_avp.name, a, a.model_avp.val_to_desc.keys()))
    elif a.model_avp.datatype == 'UTF8String':
      try:
        a.data.decode('utf-8', 'strict')
      except UnicodeDecodeError:
        violations.append(UTF8Violation(a.model_avp.name, a))

  return violations
