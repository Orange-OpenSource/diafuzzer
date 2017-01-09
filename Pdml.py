#!/usr/bin/env python

# Project     : diafuzzer
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import xml.parsers.expat
import subprocess
import sys
from struct import unpack
from binascii import a2b_hex
from socket import inet_ntoa

track_owner = False

def isgraph(c):
  return ord(c) > 0x20 and ord(c) < 0x7f

class PcapLoader(object):
  '''reads a pcap file and stores frames under self.frames.
A frame is a dictionary with the following keys:
_ 'ts': a double, representing tv_sec + tv_usec/1000000
_ 'caplen': an integer, representing captured length
_ 'len': an integer, representing original wire length
_ 'bytes': an array of bytes, the captured bytes
'''
  def __init__(self, name):
    f = open(name, 'rb')
    magic = f.read(4)
    assert(len(magic) == 4)
    (self.magic,) = unpack('=L', magic)
    if self.magic == 0xa1b2c3d4:
      swapped = '<'
    elif self.magic == 0xd4c3b2a1:
      swapped = '>'
    else:
      print >>sys.stderr, 'pcap magic unknown!'
      sys.exit(1)
    fhdr = f.read(20)
    assert(len(fhdr) == 20)
    (self.maj, self.min, self.zone, self.sigfigs,
      self.snaplen, self.dlt) = unpack(swapped + 'HHLLLL', fhdr)
    
    self.frames = []
    
    while True:
      phdr = f.read(16)
      if len(phdr) == 0:
        break
      assert(len(phdr) == 16)
      (sec, usec, caplen, l) = unpack(swapped + 'LLLL', phdr)
      content = f.read(caplen)
      assert(len(content) == caplen)
      
      self.frames.append({'ts': sec + usec*0.000001, 'caplen': caplen, 'len': l, 'bytes': bytes(content)})

class TaggedChunk(object):
  def __init__(self, owner, pos, content):
    self.owner = owner
    self.pos = pos
    self.content = content

  def __repr__(self):
    return '%r # <%s>' % (self.content, self.owner.name)

class Pdu(object):
  '''defines a Protocol Data Unit, which might spans over several frames.
It has IP source and destination, transport source and destination.
It is already dissected, and dissection is flattened to create a signature.
'''
  def __init__(self, frame, ipsrc, ipdst, ipproto, sport, dport, apps, roots):
    self.pdml = frame
    self.ipsrc = ipsrc
    self.ipdst = ipdst
    self.ipprotocol = ipproto
    if self.ipprotocol == 6:
      self.proto = 'tcp'
    elif self.ipprotocol == 17:
      self.proto = 'udp'
    elif self.ipprotocol == 132:
      self.proto = 'sctp'
    self.sport = sport
    self.dport = dport
    self.apps = apps
    self.content = None
    self.fields = []
    self.tags = []

    self.source = '%s:%d' % (self.ipsrc, self.sport)
    self.dest = '%s:%d' % (self.ipdst, self.dport)

    id = 0
    flds = roots
    
    while len(flds) > 0:
      next_flds = []

      for fld in flds:
        if fld.is_real():
          self.fields.append(fld)

        for cfld in fld.children:
          next_flds.append(cfld)

      flds = next_flds

    start = min([f.pos for f in self.fields])
    end = max([f.pos + f.size - 1 for f in self.fields])

    # Wireshark dissectors are not perfect yet
    # sometimes dissection spans wider than wireframe
    # to shield us from this, if pdu is contained in a single frame, bound logical end to frame end
    if self.pdml.reassembled is None:
      end = min([end, len(self.pdml.get_content())-1])

    self.content = self.pdml.get_content()[start:end+1]

    if not track_owner:
      return

    tagged_bytes = [None] * (end - start + 1)
    for fld in self.fields:
      fld.pos -= start
      for i in range(fld.pos, fld.pos+fld.size):
        if i < len(tagged_bytes):
          tagged_bytes[i] = fld

    for ndx in range(0, len(tagged_bytes)):
      owner = tagged_bytes[ndx]
      if owner is None:
        print >>sys.stderr, 'byte %d does not belong to any field' % ndx
        sys.exit(1)

    i = 0
    while i < len(tagged_bytes):
      owner = tagged_bytes[i]
      assert(owner is not None)
      
      s = i
      while i < len(tagged_bytes) and tagged_bytes[i] == owner:
        i += 1
       
      e = i - 1
      
      t = TaggedChunk(owner, s, self.content[s:e+1])
      self.tags.append(t)
      if len(t.content) != e - s + 1:
        print('%r' % self.content)
        print('%r' % self.content[s:])
        print('spanning %d -> %d %r' % (s, e, t.content))
        print('%d <-> %d' % (len(t.content), e - s + 1))
      assert(len(t.content) == e - s + 1)

  def __repr__(self):
    s = '[\n'
    s += ',\n'.join(['    %r' % line for line in self.content.splitlines(True)])
    s += '\n  ]'
    return s

class PdmlFrame(object):
  '''gathers PDML fields extracted by tshark, plus fragments and raw bytes.
Fields are stored with respect to their tree nature.
'''
  def __init__(self):
    self.fields = []
    self.top = None
    self.frm_number = -1
    self.protocols = None
    self.pcap = None
    self.reassembled_later = False
    self.reassembled = None
  
  def add_fragment(self, f):
    if self.reassembled is None:
      self.reassembled = f
    else:
      self.reassembled += f
  
  def get_content(self):
    if self.reassembled is not None:
      return self.reassembled
    else:
      return self.pcap['bytes']
  
  def get_slice(self, pos, size):
    return self.get_content()[pos:pos+size]

  def get_field(self, n):
    candidates = [f for f in self.fields if f.name == n]
    if len(candidates) == 0:
      return None
    return candidates[-1]

  def get_pdu(self, loader):
    if self.reassembled_later and self.reassembled is None:
      return

    fipsrc = self.get_field('ip.src')
    fipdst = self.get_field('ip.dst')
    fipprotocol = self.get_field('ip.proto')
    if fipsrc is None or fipdst is None or fipprotocol is None:
      return

    ipsrc = inet_ntoa(fipsrc.value)
    ipdst = inet_ntoa(fipdst.value)
    ipprotocol = unpack('!B', fipprotocol.value)[0]

    if ipprotocol == 6:
      fsport = self.get_field('tcp.srcport')
      fdport = self.get_field('tcp.dstport')
      ftrans = self.get_field('tcp')
      ndx = self.protocols.rfind(':tcp:')
    elif ipprotocol == 17:
      fsport = self.get_field('udp.srcport')
      fdport = self.get_field('udp.dstport')
      ftrans = self.get_field('udp')
      ndx = self.protocols.rfind(':udp:')
    elif ipprotocol == 132:
      fsport = self.get_field('sctp.srcport')
      fdport = self.get_field('sctp.dstport')
      ftrans = self.get_field('sctp')
      ndx = self.protocols.rfind(':sctp:')
    else:
      return

    if fsport is None or fdport is None or ftrans is None:
      return

    sport = unpack('!H', fsport.value)[0]
    dport = unpack('!H', fdport.value)[0]

    if ndx == -1:
      return
    apps = self.protocols[ndx+5:]

    rlabel = (ipprotocol, ipdst, dport, ipsrc, sport)
    if rlabel not in loader.flows:
      label = (ipprotocol, ipsrc, sport, ipdst, dport)
      if label not in loader.flows:
        loader.flows.append(label)

    roots = []
    collect = False

    for fld in ftrans.parent.children:
      if collect:
        roots.append(fld)

      if fld == ftrans:
        collect = True

    if len(roots) == 0:
      return

    return Pdu(self, ipsrc, ipdst, ipprotocol, sport, dport, apps, roots)

class PdmlField(object):
  '''The equivalent of a field or proto node in PDML output.
It can be of two types:
_ real: it represents a precisely located zone in the frame
_ generated: it represents an additional information derived from frame content
'''
  def __init__(self, name, parent=None, info=None):
    self.name = name
    self.parent = parent
    if self.parent is not None:
      self.parent.children.append(self)
    self.children = []
    self.info = info

  def is_real(self):
    return hasattr(self, 'pos') and hasattr(self, 'size')

  def __repr__(self):
    return '<%s>' % self.name

class PdmlLoader(object):
  def __init__(self, name, opts=[]):
    self.frames = []
    self.pdus = []
    self.name = name
    self.context = []
    self.pcap = PcapLoader(name)
    self.summaries = []
    self.start_capture_summary = False
    self.section_count = 0
    self.start_structure = False
    self.psml_sections = []
    self.flows = []

    p = xml.parsers.expat.ParserCreate()
    p.StartElementHandler = self.psml_start
    p.EndElementHandler = self.psml_end
    p.CharacterDataHandler = self.psml_data
    cmdline = ['tshark', '-n', '-r', name, '-T', 'psml']
    cmdline.extend(opts)
    psml = subprocess.Popen(cmdline,
      stdout=subprocess.PIPE)
    while True:
      buf = psml.stdout.read()
      p.Parse(buf, len(buf) == 0)
      if len(buf) == 0:
        break
    psml.wait()

    p = xml.parsers.expat.ParserCreate()
    p.StartElementHandler = self.pdml_start
    p.EndElementHandler = self.pdml_end
    cmdline = ['tshark', '-n', '-r', name, '-T', 'pdml']
    cmdline.extend(opts)
    pdml = subprocess.Popen(cmdline,
      stdout=subprocess.PIPE)
    while True:
      buf = pdml.stdout.read()
      p.Parse(buf, len(buf) == 0)
      if len(buf) == 0:
        break
    pdml.wait()

    assert(len(self.frames) == len(self.summaries))

    for ndx in range(0, len(self.frames)):
      frm = self.frames[ndx]
      pdu = frm.get_pdu(self)
      if pdu is not None:
        pdu.summary = self.summaries[ndx]
        self.pdus.append(pdu)

  def psml_start(self, name, attrs):
    if name == 'packet':
      self.start_capture_summary = True
      self.section_count = 0
      self.current_summary = []
    elif name == 'structure':
      self.start_structure = True
      self.section_count = 0
    elif name == 'section' and (self.start_capture_summary or self.start_structure):
      self.section_count += 1

  def psml_end(self, name):
    if name == 'packet':
      self.start_capture_summary = False
      self.section_count = 0
      self.summaries.append(' '.join(self.current_summary))
    elif name == 'structure':
      self.start_structure = False
      self.section_count = 0

  def psml_data(self, data):
    if self.start_structure:
      if data == 'Protocol' or data == 'Info':
        self.psml_sections.append(self.section_count)
    if self.start_capture_summary and self.section_count in self.psml_sections:
      if data != '' and data != '\n':
        self.current_summary.append(data)

  def pdml_start(self, name, attrs):
    if name == 'packet':
      frame = PdmlFrame()
      
      root = PdmlField('[root]', None)
      
      frame.fields.append(root)
      frame.top = root
      
      self.frames.append(frame)
      
      self.context.append(root)
    elif name == 'proto' or name == 'field':
      frame = self.frames[-1]
      
      fname = attrs['name']
      if 'size' in attrs:
        size = int(attrs['size'])
      else:
        size = 0
      value = None
      if 'value' in attrs:
        value = attrs['value']
      show = None
      if 'show' in attrs:
        show = attrs['show']
      masked = 'unmasked' in attrs
      
      fld = None
      
      if fname == 'geninfo' or self.context[-1].name.startswith('geninfo') or \
        fname == 'frame' or fname == 'ip.fragments' or fname == 'tcp.segments':
        fld = PdmlField(fname, self.context[-1])
      elif fname == 'frame.number':
        fld = PdmlField(fname, self.context[-1], show)
        frame.frm_number = int(show)
      elif fname == 'frame.protocols':
        fld = PdmlField(fname, self.context[-1], show)
        frame.protocols = show
      elif fname == 'frame.time_relative':
        fld = PdmlField(fname, self.context[-1], show)
      elif fname == 'ip.fragment' or fname == 'tcp.segment':
        fld = PdmlField(fname, self.context[-1])
        
        frag_number = int(show)
        for frm in self.frames:
          if frm.frm_number == frag_number:
            frm.reassembled_later = True
        
        frame.add_fragment(a2b_hex(value))
      elif size > 0:
        fld = PdmlField(fname, self.context[-1])
        
        fld.pos = int(attrs['pos'])
        fld.size = int(size)
        if masked:
          fld.non_byte = True
        fld.value = frame.get_slice(fld.pos, fld.size)
        
        if value is not None and len(value) > 0:
          #assert(a2b_hex(value) == fld.value)
          pass

      elif value is not None:
        fld = PdmlField(fname, self.context[-1], value)
      else:
        fld = PdmlField(fname, self.context[-1])
      
      assert(fld is not None)
      
      frame.fields.append(fld)
      self.context.append(fld)
    else:
      pass

  def pdml_end(self, name):
    if name == 'packet':
      assert(len(self.context) == 1)
      self.context.pop(-1)
    elif name == 'proto' or name == 'field':
      fld = self.context[-1]
      frame = self.frames[-1]
      
      if fld.name == 'frame.number':
        frame.pcap = self.pcap.frames[frame.frm_number-1]
      
      self.context.pop(-1)
