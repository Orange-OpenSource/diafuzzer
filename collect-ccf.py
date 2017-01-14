#!/usr/bin/env python

from pyparsing import alphas, alphanums, OneOrMore, Group, Literal, delimitedList
from pyparsing import Suppress as S
from pyparsing import Optional as O
from pyparsing import Word as W
from pyparsing import CaselessLiteral as CL

from subprocess import check_output

'''
Parser of CCF for message and grouped avp
'''

digits = '0123456789'
mul = Group(O(W(digits)) + '*' + O(W(digits)))

fixed_avp = '<' + W(alphanums + '_-') + '>'
mandatory_avp = '{' + W(alphanums + '_-') + '}'
optional_avp = '[' + W(alphanums + '_-') + ']'

avp = Group(O(mul) + (fixed_avp | mandatory_avp | optional_avp))

avps = Group(OneOrMore(avp))

flags = Group(delimitedList(Literal('REQ')|Literal('PXY')|Literal('ERR'), delim=','))

msg_decl = O(S('<')) + W(alphas + '_-') + O(S('>'))
msg_hdr = S('<') + S(CL('Diameter')) + S(O('-')) + S(CL('Header')) + S(':') + W(alphanums) + O(S(',')) + flags + O(S(',') + W(alphanums)) + S('>')
equals = S(':') + S(':') + S('=')
msg_ccf = msg_decl + equals + msg_hdr + avps

avp_decl = O(S('<')) + W(alphas + '_-') + O(S('>'))
avp_hdr = S('<') + S(CL('AVP')) + S(O('-')) + S(CL('Header')) + S(':') + W(alphanums) + S(O(',')) + O(W(alphanums)) + S('>')
avp_ccf = avp_decl + equals + avp_hdr + avps





'''
Ensure canonical form:
- force sort of Camel-Case used in IETF and 3gpp specs
- sort AVPs: first fixed, then mandatory, then optional. Mandatory and optional AVPs are sorted
'''

def fix_case(name):
  elms = name.split('-')
  return '-'.join([e.capitalize() for e in elms])

def order_avps(avps):
  fixed_avps = [a for a in avps if a.type == 'FIXED']
  for a in fixed_avps: a.name = fix_case(a.name)
  mandatory_avps = [a for a in avps if a.type == 'MANDATORY']
  for a in mandatory_avps: a.name = fix_case(a.name)
  optional_avps = [a for a in avps if a.type == 'OPTIONAL']
  for a in optional_avps: a.name = fix_case(a.name)

  avps = []
  avps.extend(fixed_avps)
  for a in sorted(mandatory_avps, key=lambda x: x.name):
    avps.append(a)
  for a in sorted(optional_avps, key=lambda x: x.name):
    avps.append(a)

  return avps


def dump_avps(avps):
  r = ''

  for avp in avps:
    r += '  '
    r += avp.dump()
    r += '\n'

  return r

class Msg:
  '''
Stands for a Diameter message definition, incl.:
* Command name: long form, separated by hyphens, and ending with -Request or -Answer
* Command code
* List of flags: is a request, is an error, is proxyable
* List of qualified AVPs
  '''

  def __init__(self, result):
    assert(len(result) in [4, 5])

    self.name = result[0]
    self.code = result[1]
    self.flags = result[2]
    if len(result) == 5:
      self.appid = result[3]
    else:
      self.appid = '0'
    self.avps = []
    for elm in result[-1]:
      self.avps.append(QualifiedAvp(elm))

    self.avps = order_avps(self.avps)

  def __hash__(self):
    return hash((self.code, self.appid))

  def __eq__(self, other):
    return isinstance(other, Msg) and self.code == other.code and self.appid == other.appid and self.avps == other.avps

  def dump(self):
    r = '<%s> ::= <Diameter-Header: %s, %s, %s>\n' % (self.name, self.code, ', '.join(self.flags), self.appid)
    r += dump_avps(self.avps)
    return r

class GroupedAvp:
  '''
Stands for a Diameter grouped AVP definition, incl.:
* AVP name: long form
* AVP code
* List of flags: is mandatory, is proxyable, is encrypted, is vendor-specific
* List of qualified AVPs
As such, its structure is similar to Msg defined above, except for the header part.
  '''

  def __init__(self, result):
    assert(len(result) in [3, 4])
    self.name = result[0]
    self.code = result[1]
    if len(result) == 4:
      self.vendorid = result[2]
    else:
      self.vendorid = '10415'
    self.avps = []
    for elm in result[-1]:
      self.avps.append(QualifiedAvp(elm))
    self.avps = order_avps(self.avps)

  def dump(self):
    r = '<%s> ::= <AVP-Header: %s, %s>\n' % (self.name, self.code, self.vendorid)
    r += dump_avps(self.avps)
    return r

class QualifiedAvp:
  TYPES = {
    '>': 'FIXED',
    '}': 'MANDATORY',
    ']': 'OPTIONAL'
  }

  def __init__(self, result):
    assert(len(result) in [3, 4])
    self.name = result[-2]
    self.mul = None
    if len(result) == 4:
      self.mul = ''.join(result[0])
    assert(result[-1] in QualifiedAvp.TYPES)
    self.type = QualifiedAvp.TYPES[result[-1]]

  def __hash__(self):
    return hash((self.name, self.mul, self.type))

  def __eq__(self, other):
    return isinstance(other, QualifiedAvp) and self.name == other.name and self.mul == other.mul and self.type == other.type

  def dump(self):
    r = ''
    if self.mul:
      r += '%s' % self.mul
    if self.type == 'FIXED':
      r += '<%s>' % self.name
    elif self.type == 'MANDATORY':
      r += '{%s}' % self.name
    elif self.type == 'OPTIONAL':
      r += '[%s]' % self.name
    return r

def doc2txt(arg):
  content = check_output(['catdoc', '-w', arg])
  return content

def parse_txt(content):
  cmds = []
  for cmd, start, end in msg_ccf.scanString(content):
    cmd = Msg(cmd)
    cmds.append(cmd)

  avps = []
  for avp, start, end in avp_ccf.scanString(content):
    avp = GroupedAvp(avp)
    avps.append(avp)

  return (cmds, avps)

def parse_doc(doc):
  txt = doc2txt(doc)
  return parse_txt(txt)

def parse_avps(txt):
  global avps
  for result, start, end in avps.scanString(txt):
    avps = []
    result = result[0]
    for avp in result:
      avps.append(QualifiedAvp(avp))
    return avps

def generate_dia(cmds, avps):
  r = '@messages\n'

  for cmd in cmds:
    r += cmd.dump()

  r += '@grouped\n'
  for avp in avps:
    r += avp.dump()

  return r

if __name__ == '__main__':
  import sys

  content = sys.stdin.read()
  (cmds, gavps) = parse_txt(content)
  dia = generate_dia(cmds, gavps)

  print(dia)
