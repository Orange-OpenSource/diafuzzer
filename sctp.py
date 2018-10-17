#!/usr/bin/env python2

import socket
import struct
import sys

# Monkey patch for:
# - SOCK_SEQPACKET
# - IPPROTO_SCTP
# - bindx

if not hasattr(socket, 'SOCK_SEQPACKET'):
  socket.SOCK_SEQPACKET = 5

if not hasattr(socket, 'IPPROTO_SCTP'):
  socket.IPPROTO_SCTP = 132

SCTP_BINDX_ADD_ADDR = 1
SCTP_BINDX_REM_ADDR = 2

# Load libsctp shared library
# and resolve sctp_bindx

# under x64-64 Debian 9, it resolves to /usr/lib/x86_64-linux-gnu/libsctp.so.1

import ctypes

libsctp = None
if libsctp is None:
  try:
    libsctp = ctypes.CDLL('libsctp.so')
  except:
    pass

if libsctp is None:
  try:
    libsctp = ctypes.CDLL('libsctp.so.1')
  except:
    pass

if libsctp is None:
  print('could not load SCTP shared library. Will now exit')
  sys.exit(1)
  
assert(libsctp is not None)

real_bindx = libsctp.sctp_bindx
assert(real_bindx)

real_connectx = libsctp.sctp_connectx
assert(real_connectx)


# sockaddr_in structure
class SOCKADDR_IN(ctypes.Structure):
  _fields_ = [
    ("sin_family", ctypes.c_uint16),
    ("sin_port", ctypes.c_uint16),
    ("sin_addr", ctypes.c_uint32),
    ("sin_zero", ctypes.c_byte*8),
  ]

def bindx(f, addrs):
  ADDRS_IN = SOCKADDR_IN * len(addrs)
  addrs_in = ADDRS_IN()

  for i in range(len(addrs)):
    (addr, port) = addrs[i]
    addrs_in[i].sin_family = socket.AF_INET
    addrs_in[i].sin_port = socket.htons(port)
    addrs_in[i].sin_addr = struct.unpack('<I', socket.inet_aton(addr))[0]

  return real_bindx(f.fileno(), addrs_in, len(addrs_in), SCTP_BINDX_ADD_ADDR)

def connectx(f, addrs):
  ADDRS_IN = SOCKADDR_IN * len(addrs)
  addrs_in = ADDRS_IN()

  for i in range(len(addrs)):
    (addr, port) = addrs[i]
    addrs_in[i].sin_family = socket.AF_INET
    addrs_in[i].sin_port = socket.htons(port)
    addrs_in[i].sin_addr = struct.unpack('<I', socket.inet_aton(addr))[0]

  assoc = ctypes.c_int(0)
  ret = real_connectx(f.fileno(), addrs_in, len(addrs_in), ctypes.byref(assoc))
  return ret
