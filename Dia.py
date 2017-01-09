#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import sys
import re
import os
from itertools import groupby, ifilter
from copy import deepcopy
from cPickle import dump, load

# exceptions are self-describing
class InvalidSectionOccurence(Exception): pass
class InvalidSectionArgument(Exception): pass
class MissingIdSection(Exception): pass
class MissingDefaultVendorIdSection(Exception): pass
class AVPDefinedMultipleTimes(Exception): pass
class MSGDefinedMultipleTimes(Exception): pass
class MSGContainsInvalidId(Exception): pass
class GroupedDefinitionForUnknownAVP(Exception): pass
class EnumDefinitionForUnknownAVP(Exception): pass
class AvpTypeInvalidLine(Exception): pass
class MultipleDefinitionFound(Exception): pass

class InvalidAVPType(Exception): pass
class InvalidAVPFlags(Exception): pass
class InvalidAVPQualifier(Exception): pass

class EnumeratedAVPNotValued(Exception): pass
class GroupedAVPNotDefined(Exception): pass

class MSGUsesUndefinedAVP(Exception): pass
class AVPUsesUndefinedAVP(Exception): pass

class RFC6733UnmatchedLine(Exception): pass

class EnumDuplicatedDesc(Exception): pass
class EnumDuplicatedValue(Exception): pass
class AmbiguousAVPNaming(Exception): pass

def tokenize(whole):
  tokens = []
  for l in whole.split('\n'):
    l = l.rstrip('\r\n')
    l = re.sub(r';.*', '', l)
    #l = l.replace(' ', '')

    if len(l) > 0:
      tokens.append(l)
  return tokens

QUAL_AVP = re.compile(r'\s*(\d+)?\s*(\*)?\s*(\d+)?\s*([\[\{<])\s*([a-zA-Z0-9-]+)\s*([\]\}>])')
def parse_qual_avp(l):
  m = QUAL_AVP.match(l)
  if m:
    (_min, times, _max, s_delim, avp_name, e_delim) = m.groups()
    paren = (s_delim, e_delim)
    if paren == ('<', '>'): avp_type = 'fixed'
    elif paren == ('[', ']'): avp_type = 'optional'
    elif paren == ('{', '}'): avp_type = 'required'
    else:
      raise InvalidAvpQualifier(l)

    times = times is not None
    return QualifiedAvp(times, _min, _max, avp_type, avp_name)

# warning: despite what is described in rfc6733
# rfc6733 itself uses a wrong format for its CCF such as DPR, DWR and CER
# ...
# in short: command name must not be enclosed in angle brackets
CMD_DEF = re.compile(r'\s*([a-zA-Z0-9-]+)\s*::\s*=\s*<\s*Diameter[- ]Header\s*:\s*(\d+)((?:\s*,\s*(?:REQ|PXY|ERR))*)(?:\s*,\s*(\d+))?\s*>')
def parse_ccf(l):
  m = CMD_DEF.search(l)
  if m:
    (name, code, flags, appid) = m.groups()

    flaglist = [f.group(1) for f in re.finditer(r'\s*,\s*(REQ|PXY|ERR|\d+)', flags)]
    if appid is None or appid == '': appid = 0
    else: appid = int(appid, 0)

    return (name, int(code, 0), flaglist, appid)
  
GAV_DEF = re.compile(r'\s*([a-zA-Z0-9-]+)\s*::\s*=\s*<\s*AVP[- ][Hh]eader\s*:\s*(\d+)(?:\s*,?\s*(\d+))?\s*>')
def parse_gav(l):
  m = GAV_DEF.search(l)
  if m:
    (name, code, vendor_id) = m.groups()
    return (name, int(code, 0), vendor_id)

def parse_6733(whole, hdr):
  '''parse structure as hdr qual_avp*.
Two cases for now in rfc6733: Diameter CCF, and grouped AVP'''
  ongoing_elm = None
  avps = []

  for l in tokenize(whole):
    if not ongoing_elm:
      m = hdr(l)
      if not m:
        print >>sys.stderr, 'failed to parse %r' % l
      assert(m)

      ongoing_elm = m
      avps = []
    else:
      m = parse_qual_avp(l)
      if m:
        avps.append(m)
      else:
        m = hdr(l)
        if not m:
          raise RFC6733UnmatchedLine(ongoing_elm, avps, l)

        yield (ongoing_elm, avps)

        ongoing_elm = m
        avps = []

  yield (ongoing_elm, avps)

def parse_msgs(whole): return parse_6733(whole, parse_ccf)
def parse_grouped(whole): return parse_6733(whole, parse_gav)

class Avp:
  BASIC_DATATYPES = ['OctetString', 'Integer32', 'Integer64',
    'Unsigned32', 'Unsigned64', 'Float32', 'Float64', 'Grouped']
  DERIVED_DATATYPES = ['Address', 'Time', 'UTF8String', 'Enumerated',
    'DiameterIdentity', 'DiamIdent', 'DiameterURI', 'DiamURI', 'IPFilterRule', 'QoSFilterRule']

  KNOWN_LENGTH_DATATYPES = {
    'Integer32': [4],
    'Integer64': [8],
    'Unsigned32': [4],
    'Unsigned64': [8],
    'Float32': [4],
    'Float64': [8],
    'Address': [2+4, 2+16],
    'Time': [8],
    'Enumerated': [4],
    'Time': [4],
  }

  def __hash__(self):
    return hash((self.code, self.vendor_id))

  def __eq__(self, other):
    return (self.code, self.vendor_id) == (other.code, other.vendor_id)

  def __init__(self, name, code, datatype, flags):
    self.name = name
    self.code = int(code, 0)
    self.vendor_id = 0

    if datatype not in Avp.BASIC_DATATYPES and \
      datatype not in Avp.DERIVED_DATATYPES:
      raise InvalidAVPType(datatype)
    if datatype == 'DiamIdent': datatype = 'DiameterIdentity'
    if datatype == 'DiamURI': datatype = 'DiameterURI'
    self.datatype = datatype

    if flags != '-' and any(c not in 'MVP' for c in flags):
      raise InvalidAVPFlags(flags)

    self.M = self.P = self.V = False
    for c in flags:
      if c == 'M': self.M = True
      if c == 'V': self.V = True
      if c == 'P': self.P = True

  def __repr__(self):
    return self.name

  def to_type(self):
    flags = ''
    if self.M: flags += 'M'
    if self.V: flags += 'V'
    if self.P: flags += 'P'
    if flags == '': flags = '-'

    return '%-45s\t%-9d\t%-20s\t%-4s' % (self.name, self.code, self.datatype, flags)

  def allows_stacking(self):
    if self.datatype != 'Grouped':
      return False

    for qa in self.grouped:
      if qa.name == 'AVP' and qa.min is None and qa.max is None:
        return True

    return False

class QualifiedAvp:
  def __init__(self, multiple, occ_min, occ_max, semantics, name):
    self.name = name
    self.min = occ_min
    if occ_min: self.min = int(occ_min)
    self.multiple = multiple
    self.max = occ_max
    if occ_max: self.max = int(occ_max)

    assert(semantics in ['fixed', 'required', 'optional'])
    self.semantics = semantics
    self.avp = None

  def __repr__(self):
    if self.semantics == 'fixed':
      decorated = '< %s >' % self.name
    elif self.semantics == 'required':
      decorated = '{ %s }' % self.name
    elif self.semantics == 'optional':
      decorated = '[ %s ]' % self.name

    qual = ''
    if self.multiple:
      if self.min:
        qual += '%2d' % self.min
      else:
        qual += '  '
      qual += '*'
      if self.max:
        qual += '%2d' % self.max
      else:
        qual += '  '
    else:
      qual += ' '*5

    return '%s %s' % (qual, decorated)

  def accept(self, cnt):
    if self.semantics == 'fixed':
      if not self.multiple: return cnt == 1
      else:
        if self.min and self.min > cnt: return False
        if self.max and self.max < cnt: return False
        return True
    elif self.semantics == 'required':
      if not self.multiple: return cnt == 1
      else:
        if self.min and self.min > cnt: return False
        if self.max and self.max < cnt: return False
        return True
    elif self.semantics == 'optional':
      if not self.multiple: return cnt == 1 or cnt == 0
      else: return True
    assert(False)

class Msg:
  def __init__(self, name, code, flags, appid):
    self.name = name
    self.code = code

    self.R = self.P = self.E = False
    for f in flags:
      if f == 'REQ': self.R = True
      if f == 'PXY': self.P = True
      if f == 'ERR': self.E = True

    self.appid = appid

  def __repr__(self):
    flags = []
    if self.R: flags.append('REQ')
    if self.P: flags.append('PXY')
    if self.E: flags.append('ERR')

    flags = ', '.join(flags)
    r = '%s ::= <Diameter Header: %d' % (self.name, self.code)
    if len(flags) > 0:
      r += ', %s' % (flags)
    if self.appid > 0:
      r += ', %d' % self.appid
    r += '>\n'

    for a in self.avps:
      r += '%r\n' % a
    return r

class Application:
  LOADED_DICTS = {}
  DIA_PATH = ['./specs']

  @staticmethod
  def load(f):
    # read whole file at once
    with open(f, 'rb') as fh:
      whole = fh.read()

    app = Application()

    # split sections
    for m in re.finditer(r'^@(\w+)((?:[ \t]+(?:[a-zA-Z0-9-_]+))*)\s*$([^@]*)', whole, re.S|re.M):
      assert(len(m.groups()) == 3)
      (name, args, content) = m.groups()
      arglist = []
      for a in re.finditer(r'[a-zA-Z0-9-_]+', args, re.S|re.M):
        arglist.append(a.group(0))

      if name == 'id':
        if app.id is not None: raise InvalidSectionOccurence()
        if len(arglist) != 1: raise InvalidSectionArgument()
        app.id = int(arglist[0], 0)
      elif name == 'name':
        if app.name is not None: raise InvalidSectionOccurence()
        if len(arglist) not in [1, 2]: raise InvalidSectionArgument()
        app.name = arglist[0]
        if len(arglist) == 2:
          app.version = arglist[1]
      elif name == 'vendor':
        if app.default_vendor_id is not None: raise InvalidSectionOccurence()
        if len(arglist) != 2: raise InvalidSectionArgument()
        app.default_vendor_id = int(arglist[0], 0)
        app.default_vendor_name = arglist[1]
      elif name == 'avp_vendor_id':
        if len(arglist) != 1: raise InvalidSectionArgument()
        app.avp_vendors.append((int(arglist[0], 0), tokenize(content)))
      elif name == 'inherits':
        if len(arglist) != 1: raise InvalidSectionArgument()
        app.inherits.append((arglist[0], tokenize(content)))
      elif name == 'avp_types':
        for l in tokenize(content):
          if len(l.split()) != 4: raise AvpTypeInvalidLine(l)

          (name, code, datatype, flags) = l.split()
          if app.find_avps(lambda x: x.code == int(code, 0)):
            raise AVPDefinedMultipleTimes(code)

          a = Avp(name, code, datatype, flags)
          app.avps.append(a)
      elif name == 'messages':
        for (msg, avps) in parse_msgs(content):
          (name, code, flags, appid) = msg
          if app.find_msgs(lambda x: x.name == name):
            raise MSGDefinedMultipleTimes(name)

          if appid and app.id and appid != app.id:
            raise MSGContainsInvalidId(appid)

          m = Msg(name, code, flags, appid)
          m.avps = avps

          app.msgs.append(m)
      elif name == 'grouped':
        app.grouped.append([m for m in parse_grouped(content)])
      elif name == 'enum':
        if len(arglist) != 1: raise InvalidSectionArgument()
        app.enums.append((arglist[0], [l.split() for l in tokenize(content)]))
      elif name in ['prefix', 'custom_types', 'codecs', 'end']:
        print >>sys.stderr, '*** ignoring section %s' % name
        pass

    # need an id if msgs are contained in the dictionary
    if app.msgs and app.id is None:
      raise MissingIdSection(f, 'id')
    for m in app.msgs:
      m.appid = app.id

    # by default, name is set to name of file, without extension
    if app.name is None:
      basename = os.path.basename(f)
      app.name = basename.split(os.extsep)[0]

    # lookup and load inherited modules
    for (m, avps) in app.inherits:
      mod_found = False

      for dpath in Application.DIA_PATH:
        modpath = os.path.join(dpath, m + '.dia')
        if os.path.exists(modpath):
          mod = Application.load(modpath)

          if not avps: avps = [x.name for x in mod.avps]
          for a in avps:
            inherited = mod.find_avps(lambda x: x.name == a)
            if len(inherited) != 1:
              print >>sys.stderr, 'warning: several AVPs are named the same %r' % inherited
            app.inherited_avps.extend(inherited)

          app.inherited_msgs.extend(mod.msgs)

          mod_found = True
          break

      if not mod_found:
        print >>sys.stderr, '!!! inherit from %s failed' % m
        sys.exit(1)

    # process enum definitions
    for (name, values) in app.enums:
      avps = app.find_avps(lambda x: x.name == name)
      if len(avps) > 1: raise AVPDefinedMultipleTimes(name)
      if len(avps) == 0: raise EnumDefinitionForUnknownAVP(name)

      a = avps[0]
      a.val_to_desc = {}
      a.desc_to_val = {}


      for (desc, val) in values:
        if desc in a.desc_to_val: raise EnumDuplicatedDesc(desc, a)
        if val in a.val_to_desc: raise EnumDuplicatedValue(val, a)

        n = int(val, 0)
        a.val_to_desc[n] = desc
        a.desc_to_val[desc] = n

    # process grouped definitions
    for gs in app.grouped:
      for (gav, gavps) in gs:
        (name, code, vendor_id) = gav
        avps = app.find_avps(lambda x: x.name == name)
        if len(avps) == 0: raise GroupedDefinitionForUnknownAVP(name)

        a = avps[0]
        a.grouped = gavps

    # set vendor id for specified AVPs
    for (vendor, avps) in app.avp_vendors:
      for a in app.avps:
        if a.name in avps: a.vendor = vendor
    # vendor AVP need a default vendor id, when vendor id is not specified in AVP itself
    for a in app.avps:
      if a.V and not a.vendor_id:
        if app.default_vendor_id is None: raise MissingDefaultVendorIdSection('vendor_id')
        a.vendor_id = app.default_vendor_id

    # consistency checks
    for a in app.avps:
      if a.datatype == 'Enumerated':
        if not hasattr(a, 'val_to_desc') or not a.val_to_desc:
          raise EnumeratedAVPNotValued(a.name)
      if a.datatype == 'Grouped':
        if not hasattr(a, 'grouped') or not a.grouped:
          raise GroupedAVPNotDefined(a.name)

    app.verify()

    Application.LOADED_DICTS[app.name] = app

    return app

  @staticmethod
  def lookup_msg(f):
    msgs = []
    for n in Application.LOADED_DICTS:
      for m in Application.LOADED_DICTS[n].msgs:
        if f(m):
          msgs.append(m)
    return msgs

  def verify(self):
    # definition checks
    for m in self.msgs:
      for qa in m.avps:
        if qa.name != 'AVP':
          avps = self.find_avps(lambda x: x.name == qa.name)
          if len(avps) == 0:
            raise MSGUsesUndefinedAVP(m.name, qa.name)
          if len(avps) != 1:
            raise AmbiguousAVPNaming(m.name, qa.name)
          qa.avp = avps[0]

    for a in self.avps:
      if a.datatype == 'Grouped':
        for qa in a.grouped:
          if qa.name != 'AVP':
            avps = self.find_avps(lambda x: x.name == qa.name)
            if len(avps) == 0:
              raise AVPUsesUndefinedAVP(a.name, qa.name)
            if len(avps) != 1:
              raise MultipleDefinitionFound(a.name, qa.name)
            qa.avp = avps[0]

  def __init__(self):
    self.id = None
    self.name = None
    self.version = None
    self.default_vendor_id = None
    self.default_vendor_name = None
    self.avp_vendors = []
    self.inherits = []
    self.avps = []
    self.inherited_avps = []
    self.msgs = []
    self.inherited_msgs = []
    self.enums = []
    self.grouped = []

  def find_avps(self, f=lambda x: True):
    avps = []
    for a in self.avps:
      if f(a): avps.append(a)
    for a in self.inherited_avps:
      if f(a): avps.append(a)
    return avps

  def find_msgs(self, f):
    msgs = []
    for m in self.msgs:
      if f(m): msgs.append(m)
    for m in self.inherited_msgs:
      if f(m): msgs.append(m)
    return msgs

  def __repr__(self):
    r = ''
    if self.id:
      r += '@id\t%s\n' % self.id

    if self.name and self.version:
      r += '@name\t%s\t%s\n\n' % (self.name, self.version)
    elif self.name:
      r += '@name\t%s\n\n' % self.name

    if self.default_vendor_id:
      r += '@vendor\t%d\t%s\n\n' % (self.default_vendor_id, self.default_vendor_name)

    if self.inherits:
      for (m, avps) in self.inherits:
        r += '@inherits\t%s' % m
        for a in avps:
          r += '%s' % a
        r += '\n'
      
    if self.avps:
      r += '@avp_types\n'
      for a in sorted(self.avps, key=lambda x: x.code):
        r += a.to_type() + '\n'
      r += '\n'

      for v, avps in groupby(ifilter(lambda x: x.V, self.avps),
        key=lambda x: x.vendor_id):
        if v is None: continue
        r += '@avp_vendor_id\t%d\n' % v
        for a in avps:
          r += a.name + '\n'
        r += '\n'

    if self.msgs:
      r += '\n@messages\n'
      for m in self.msgs:
        r += '%r' % m
        r += '\n'

    if any(a.datatype == 'Grouped' for a in self.avps):
      r += '@grouped\n'
      for a in self.avps:
        if a.datatype == 'Grouped':
          r += '%s ::= <AVP Header: %d>\n' % (a.name, a.code)
          for ga in a.grouped:
            r += '%r\n' % ga
      r += '\n'

    for a in self.avps:
      if a.datatype == 'Enumerated':
        r += '@enum %s\n' % a.name
        values = a.val_to_desc.keys()
        values = sorted(values)
        for v in values:
          r += '%-45s\t%d\n' % (a.val_to_desc[v].upper(), v)
        r += '\n'

    return r

class NonExistingAppID(Exception): pass
class NonSpecifiedMsg(Exception): pass
class MultipleSpecifiedMsg(Exception): pass

class Directory:
  def __init__(self, *args):
    self.ids = {}
    self.apps = []

    if len(args) == 0:
      args = [
        # IETF applications
        'specs/base_rfc6733.dia', 'specs/credit_rfc4006.dia',
        'specs/eap_rfc4072.dia', 'specs/mip6a_rfc5778.dia',
        'specs/mip6i_rfc5778.dia', 'specs/mobipv4_rfc4004.dia',
        'specs/nasreq_rfc7155.dia', 'specs/sip_rfc4740.dia',
        # 3GPP applications
        'specs/Cx.dia', 'specs/S13.dia', 'specs/S6a.dia',
        'specs/S6b.dia', 'specs/S7a.dia', 'specs/S9.dia',
        'specs/Sh.dia', 'specs/SWx.dia', 'specs/Rx.dia',
        'specs/Gx.dia', 'specs/Gxx.dia', 'specs/SWm.dia',
        'specs/SLg.dia', 'specs/SLh.dia']

    for arg in args:
      app = Application.load(arg)

      if app.id not in self.ids:
        self.ids[app.id] = []
      self.ids[app.id].append(app)
      self.apps.append(app)

  def find_msgs(self, appid, code, req):
    if appid not in self.ids: raise NonExistingAppID(appid)
    msgs = []
    for app in self.ids[appid]:
      msgs.extend(app.find_msgs(lambda x: x.appid == appid and x.code == code and x.R == req))
    return msgs

  def find_avps(self, vendor, code):
    avps = set()
    for app in self.apps:
      if vendor == 0:
        for a in app.find_avps(lambda x: not x.V and x.code == code):
          avps.add(a)
      else:
        for a in app.find_avps(lambda x: x.V and x.vendor_id == vendor and x.code == code):
          avps.add(a)
    return [a for a in avps]

  def find_avps_by_app(self, appid, vendor, code):
    if appid not in self.ids: raise NonExistingAppID()
    avps = []
    for app in self.ids[appid]:
      if vendor == 0:
        for a in app.find_avps(lambda x: not x.V and x.code == code):
          avps.append(a)
      else:
        for a in app.find_avps(lambda x: x.V and x.vendor_id == vendor and x.code == code):
          avps.append(a)
    return avps

  DEFAULT = None

  @staticmethod
  def tag(wire_msg):
    if Directory.DEFAULT is None:
      Directory.DEFAULT = load(open('.dia-cache', 'rb'))

    def find_matching_qa(wire_avp, model_qavps):
      '''find matching qualified avp in given list.'''
      wildcard = None
      for qa in model_qavps:
        if qa.name == 'AVP': wildcard = qa
      if not wire_avp.V:
        vendor_id = 0
      else:
        vendor_id = wire_avp.vendor
      code = wire_avp.code

      for qa in model_qavps:
        if qa.avp and vendor_id == qa.avp.vendor_id and code == qa.avp.code:
          return qa

      return wildcard

    def find_matching_avp(wire_avp):
      '''find matching model avp given vendor and code.'''
      if not wire_avp.V:
        vendor_id = 0
      else:
        vendor_id = wire_avp.vendor
      code = wire_avp.code

      for a in Directory.DEFAULT.find_avps(vendor_id, code):
        return a
 
      return None

    def avps_tag(wire_avps, model_qavps):
      '''tag an array of AVPs given an array of qualified AVPs.'''

      for a in wire_avps:
        model_qa = find_matching_qa(a, model_qavps)

        # will be None if AVP is not in model (grouped or message format)
        a.qualified_avp = model_qa

        # will be None if AVP is not in model and is unknown
        if a.qualified_avp and a.qualified_avp.avp is not None:
          a.model_avp = a.qualified_avp.avp
        else:
          a.model_avp = find_matching_avp(a)

        assert(hasattr(a, 'model_avp') and hasattr(a, 'qualified_avp'))

        if a.model_avp is not None and a.model_avp.datatype == 'Grouped':
          avps_tag(a.avps, a.model_avp.grouped)

    model_msgs = Directory.DEFAULT.find_msgs(wire_msg.app_id, wire_msg.code, wire_msg.R)
    if len(model_msgs) == 0: raise NonSpecifiedMsg(wire_msg)
    if len(model_msgs) > 1: raise MultipleSpecifiedMsg(wire_msg)
    wire_msg.model = model_msgs[0]

    avps_tag(wire_msg.avps, wire_msg.model.avps)
