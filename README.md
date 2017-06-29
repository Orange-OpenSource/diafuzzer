<a href="https://scan.coverity.com/projects/11469">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/11469/badge.svg"/>
</a>

# diafuzzer
Diameter fuzzer, based on specifications of Diameter applications following rfc 3588 / 6733

## Overview

**Diafuzzer** is composed of several different tools:

- _simple and accurate_ Diameter callflows, based on pcap traces
- _script language_ to perform additional functions such as logging, database lookup or others
- _detailed description_ of Diameter applications defined at _3GPP_ and _ETSI_
- runtime helpers to perform _unit testing and fuzz testing_

It is developped in Python, with four major components:

- **Diameter.py**: contains Python classes named Msg and Avp which mirror wire. Both classes implement default values for unspecified fields, and compute fields which value depends on other fields.
- **Dia.py**: parses _dia_ files. It contains Python classes to model message structure and avp cardinality, plus their datatype.
- **pcap2scn.py and pcap2pdu.py**: shall be given a pcap file as first argument. They will both produce a Python form of Diameter PDUs contained in trace, based on **Diameter.py** module above. **pcap2scn.py** will produce a client and/or server scenario, made of interleaved send and receive operations, whereas **pcap2pdu.py** will only dump PDUs as objects.
- **unit.py and fuzz.py**: shall be given four arguments, amongst which a scenario, and a role. **unit.py** will replay the given scenario, and **fuzz.py** will use scenario as a baseline to produce fuzzing operations.

It is not compatible with Python3.

### Diameter.py

#### Avp usage 

**Make sure to import Avp class from Diameter module**

```
>>> from Diameter import Avp
```

To create an Avp instance:

```
>>> a = Avp()
>>> a
Avp(code=0,vendor=0)
```
The following parameters can be given when building a new instance:

Parameter | Default value when not specified |  Meaning
--------- | ------------------- | -----
code      | 0 | AVP code
V         | False | AVP Vendor bit
M         | False | AVP Mandatory bit
P         | False | AVP Protected bit
reserved  | None | reserved bits (5 bits)
vendor    | 0 | vendor id (32 bits)
avps      | [] | inner AVPs
data      | None | value
length    | None, will be computed during encoding | length (32 bits)

For example, to create an Origin-Host Avp instance:

```
>>> Avp(code=264, data='hss.openims.test')
Avp(code=264, vendor=0, data='hss.openims.test')
```

Several ways are provided to supply values instead of raw bytes:

```
>>> Avp(code=266, u32=323)
Avp(code=266, vendor=0, data='\x00\x00\x01C')
```

The table below gives parameter names that can be used, and their format:

Parameter | Format | Argument type
--------- | ------ | -------------
u32       | !L     | Integer
s32       | !I     | Integer
u64       | !Q     | Integer
f32       | !f     | Float
f64       | !d     | Float

To create a wire-ready version of the instance:

```
>>> Avp(code=266, u32=323).encode()
'\x00\x00\x01\n\x00\x00\x00\x0c\x00\x00\x01C'
```

To create an instance from raw bytes:

```
>>> Avp.decode('\x00\x00\x01\n\x00\x00\x00\x0c\x00\x00\x01C')
Avp(code=266, vendor=0, data='\x00\x00\x01C')
```

#### Msg usage

**Make sure to import Msg and Avp classes from Diameter module**

```
>>> from Diameter import Msg, Avp
```

To create a Msg instance:

```
>>> m = Msg()
>>> m
Msg(code=0, app_id=0x0, avps=[
])
```


Parameter | Default value when not specified | Meaning
--------- | ------------------- | -------
version   | 1 | version (8 bits)
length    | None, will be computed during encoding | length (32 bits)
R         | False | Request bit
P         | False | Proxyable bit
E         | False | Error bit
T         | False | reTransmitted bit
reserved  | None, will be set to zeros | reserved bits (4 bits)
code      | 0 | code (32 bits)
app_id    | 0 | application ID (32 bits)
e2e_id    | None, will be randomly generated during encoding | end-to-end ID (32 bits)
h2h_id    | None, will be randomly generated during encoding | hop-by-hop ID (32 bits)
avps      | [] | inner AVPs

For example, to create a Device-Watchdog Request Msg instance:

```
>>> m = Msg(code=280, R=True)
>>> m
Msg(R=True, code=280, app_id=0x0, avps=[
])
```

In order to create a real-world Capabilities-Exchange Request Msg instance:

```
>>> m = Msg(R=True, code=257, app_id=0x0, avps=[
...   Avp(code=264, M=True, vendor=0, data='127.0.0.1'),
...   Avp(code=296, M=True, vendor=0, data='org.domain.com'),
...   Avp(code=257, M=True, vendor=0, data='\x00\x01\x7f\x00\x00\x01'),
...   Avp(code=266, M=True, vendor=0, data='\x00\x00\x00\x00'),
...   Avp(code=269, M=True, vendor=0, data='Mu Service Analyzer Diameter Implementation'),
...   Avp(code=299, M=True, vendor=0, data='\x00\x00\x00\x00'),
...   Avp(code=260, M=True, vendor=0, avps=[
...     Avp(code=266, M=True, vendor=0, data='\x00\x00(\xaf'),
...     Avp(code=258, M=True, vendor=0, data='\x01\x00\x00\x00'),
...   ]),
... ])
>>> m
Msg(R=True, code=257, app_id=0x0, avps=[
  Avp(code=264, M=True, vendor=0, data='127.0.0.1'),
  Avp(code=296, M=True, vendor=0, data='org.domain.com'),
  Avp(code=257, M=True, vendor=0, data='\x00\x01\x7f\x00\x00\x01'),
  Avp(code=266, M=True, vendor=0, data='\x00\x00\x00\x00'),
  Avp(code=269, M=True, vendor=0, data='Mu Service Analyzer Diameter Implementation'),
  Avp(code=299, M=True, vendor=0, data='\x00\x00\x00\x00'),
  Avp(code=260, M=True, vendor=0, avps=[
    Avp(code=266, M=True, vendor=0, data='\x00\x00(\xaf'),
    Avp(code=258, M=True, vendor=0, data='\x01\x00\x00\x00'),
  ]),
])
```

Encoding and decoding to/from raw bytes work the same as for Avp:

```
>>> m = Msg.decode('\x01\x00\x00\xbc\x80\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x08@\x00\x00\x11127.0.0.1\x00\x00\x00\x00\x00\x01(@\x00\x00\x16org.domain.com\x00\x00\x00\x00\x01\x01@\x00\x00\x0e\x00\x01\x7f\x00\x00\x01\x00\x00\x00\x00\x01\n@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x01\r@\x00\x003Mu Service Analyzer Diameter Implementation\x00\x00\x00\x01+@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x00')
>>> m
Msg(R=True, code=257, app_id=0x0, avps=[
  Avp(code=264, M=True, vendor=0, data='127.0.0.1'),
  Avp(code=296, M=True, vendor=0, data='org.domain.com'),
  Avp(code=257, M=True, vendor=0, data='\x00\x01\x7f\x00\x00\x01'),
  Avp(code=266, M=True, vendor=0, data='\x00\x00\x00\x00'),
  Avp(code=269, M=True, vendor=0, data='Mu Service Analyzer Diameter Implementation'),
  Avp(code=299, M=True, vendor=0, data='\x00\x00\x00\x00'),
  Avp(code=260, M=True, vendor=0, avps=[
    Avp(code=266, M=True, vendor=0, data='\x00\x00(\xaf'),
    Avp(code=258, M=True, vendor=0, data='\x01\x00\x00\x00'),
  ]),
])
>>> m.encode()
'\x01\x00\x00\xbc\x80\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x08@\x00\x00\x11127.0.0.1\x00\x00\x00\x00\x00\x01(@\x00\x00\x16org.domain.com\x00\x00\x00\x00\x01\x01@\x00\x00\x0e\x00\x01\x7f\x00\x00\x01\x00\x00\x00\x00\x01\n@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x01\r@\x00\x003Mu Service Analyzer Diameter Implementation\x00\x00\x00\x01+@\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x01\x04@\x00\x00 \x00\x00\x01\n@\x00\x00\x0c\x00\x00(\xaf\x00\x00\x01\x02@\x00\x00\x0c\x01\x00\x00\x00'
```

### Dia.py

#### Dia file format

The file format is based on a sequence of sections, each section beginning with

```
@<keyword> ...
...
```

Depending on the keyword, arguments may follow, and content of section may not be empty.

The example below defines one of the S13 application message:

```
@id     16777252
@name   S13

@inherits       ietf-avps
@inherits       3gpp-avps

@messages
ME-Identity-Check-Request ::= <Diameter Header: 324, REQ, PXY, 16777252>
      < Session-Id >
      [ Vendor-Specific-Application-Id ]
      { Auth-Session-State }
      { Origin-Host }
      { Origin-Realm }
      [ Destination-Host ]
      { Destination-Realm }
      { Terminal-Information }
      [ User-Name ]
  *   [ AVP ]
  *   [ Proxy-Info ]
  *   [ Route-Record ]
```
	
Application are defined using an id and a name:

```
@id     16777252
@name   S13
```

Most applications will use AVPs inherited from both IETF and 3GPP:

```
@inherits       ietf-avps
@inherits       3gpp-avps
```

Messages are defined using their Command Code format:

```
@messages
ME-Identity-Check-Request ::= <Diameter Header: 324, REQ, PXY, 16777252>
      < Session-Id >
      [ Vendor-Specific-Application-Id ]
      { Auth-Session-State }
      { Origin-Host }
      { Origin-Realm }
      [ Destination-Host ]
      { Destination-Realm }
      { Terminal-Information }
      [ User-Name ]
  *   [ AVP ]
  *   [ Proxy-Info ]
  *   [ Route-Record ]
```

AVPs are defined by their code, datatype and flags:

```
@avp_types
User-Name                                       1               UTF8String              M
User-Password                                   2               OctetString             M
NAS-IP-Address                                  4               OctetString             M
NAS-Port                                        5               Unsigned32              M
```

For AVP of type Grouped, the corresponding Command Code format must be defined in a grouped section:

```
@grouped
Vendor-Specific-Application-Id ::= <AVP Header: 260>
      { Vendor-Id }
      [ Auth-Application-Id ]
      [ Acct-Application-Id ]

Failed-AVP ::= <AVP Header: 279>
 1*   { AVP }
```

For AVP of type Enumerated, the corresponding values must defined in an enum section, with AVP name in argument:

```
@enum Timezone-Flag
UTC                                             0
LOCAL                                           1
OFFSET                                          2

@enum QoS-Semantics
QOS_DESIRED                                     0
QOS_AVAILABLE                                   1
QOS_DELIVERED                                   2
MINIMUM_QOS                                     3
QOS_AUTHORIZED                                  4
```

#### Supported applications

application name | Dia file | Reference
--------- | ---------| ----------
S6a   | specs/S6a.dia | [29.272](http://www.3gpp.org/DynaReport/29272.htm)
S6b   | specs/S6b.dia | [29.273](http://www.3gpp.org/DynaReport/29273.htm)
SWx   | specs/SWx.dia | [29.273](http://www.3gpp.org/DynaReport/29273.htm)
SWm   | specs/SWm.dia | [29.273](http://www.3gpp.org/DynaReport/29273.htm)
Sh    | specs/Sh.dia  | [29.329](http://www.3gpp.org/DynaReport/29329.htm)
Cx    | specs/Cx.dia  | [29.229](http://www.3gpp.org/DynaReport/29229.htm)
S7a   | specs/S7a.dia | [29.272](http://www.3gpp.org/DynaReport/29272.htm)
S13   | specs/S13.dia | [29.272](http://www.3gpp.org/DynaReport/29272.htm)
Gx    | specs/Gx.dia  | [29.212](http://www.3gpp.org/DynaReport/29212.htm)
Gxx   | specs/Gxx.dia | [29.212](http://www.3gpp.org/DynaReport/29212.htm)
Rx    | specs/Rx.dia  | [29.214](http://www.3gpp.org/DynaReport/29214.htm)
SLg   | specs/SLg.dia | [29.172](http://www.3gpp.org/DynaReport/29172.htm)
SLh   | specs/SLh.dia | [29.173](http://www.3gpp.org/DynaReport/29173.htm)
STa   | specs/STa.dia | [29.273](http://www.3gpp.org/DynaReport/29273.htm)
S9    | specs/S9.dia  | [29.215](http://www.3gpp.org/DynaReport/29215.htm)

#### Dia.py

This module holds the following classes:

- **Avp**: an AVP, most notably its datatype, plus its Command Code format or legitimate values when applicable.
- **QualifiedAvp**: an AVP and its multiplicity, in the context of a Command Code format.
- **Msg**: a message, most notably a command code, plus a list a QualifiedAvp instance.
- **Application**: an application, containing a set of messages.
- **Directory**: a set of applications. The file _.dia-cache_ contains a Directory instance containing the compiled version of dia files.

Dia files are _verified and compiled_. This serves two purposes:

- references are resolved: for example if a message definition references an AVP, one makes sure that AVP is defined
- once verified, the whole model can be compiled to Python and pickled for later faster reuse

Typical usage of pickled model include:

- _conformance verification_
- _fuzzing_, based on associated datatype or inner structure

The set of all supported applications are grouped in a Directory instance, which is pickled into _.dia-cache_ file.

**Thus any change to dia files contained in specs directory must be followed by a generation of this _.dia-cache_ file**

The script generate-cache.py will generate this file, and print supported applications:

```
$ ./generate-cache.py
creating Directory instance, this might take a while ...
created in 0:00:11.551822 dumping to .dia-cache
contains the following applications:
base_rfc6733		0 (0x0)
...
Cx		16777216 (0x1000000)
S13		16777252 (0x1000024)
S6a		16777251 (0x1000023)
S6b		16777272 (0x1000038)
S7a		16777308 (0x100005c)
Sh		16777217 (0x1000001)
SWx		16777265 (0x1000031)
Rx		16777236 (0x1000014)
Gx		16777224 (0x1000008)
Gxx		16777266 (0x1000032)
SWm		16777264 (0x1000030)
SLg		16777255 (0x1000027)
SLh		16777291 (0x100004b)
``` 

#### Adding or modifying an AVP

AVPs are defined in one of the files below:

- specs/ietf-avps.dia
- specs/3gpp-avps.dia
- specs/3gpp2-avps.dia
- specs/etsi-avps.dia

```
@avp_types
User-Name                                       1               UTF8String              M
User-Password                                   2               OctetString             M
NAS-IP-Address                                  4               OctetString             M
NAS-Port                                        5               Unsigned32              M
...
@grouped
Vendor-Specific-Application-Id ::= <AVP Header: 260>
      { Vendor-Id }
      [ Auth-Application-Id ]
      [ Acct-Application-Id ]

...
@enum QoS-Semantics
QOS_DESIRED                                     0
QOS_AVAILABLE                                   1
QOS_DELIVERED                                   2
MINIMUM_QOS                                     3
QOS_AUTHORIZED                                  4
```

There are up to two places to be modified:

- for Grouped AVP: declare new AVP in @avp_types section, and add Command Code format in @grouped section
- for Enumerated AVP: declare new AVP in @avp_types section, and add a new @enum section with the name of new AVP, containing the possible values and their meaning
- for the rest of datatypes: declare AVP in @avp_types section

**Once the modification is done, generate _.dia-cache_ as outlined above.**

#### Adding a new application

When adding a new application, one needs to append the name of the new dia file in Dia.py, at the beginning of Directory \_\_init\_\_ method.

For example to add a fictive S42 application, one has to create a dia file called specs/S42.dia, and modify Dia.py accordingly:

```
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
        'specs/S6b.dia', 'specs/S7a.dia', 'specs/Sh.dia',
        'specs/SWx.dia', 'specs/Rx.dia', 'specs/Gx.dia', 'specs/Gxx.dia',
        'specs/SWm.dia', 'specs/SLg.dia', 'specs/SLh.dia',
        
        
        # new S42 application
        'specs/S42.dia']
```

When supporting a new application, it can be convenient to check for AVP definitions and references. The script lean.py can be used to check definitions:

```
$ ./lean.py specs/S42.dia
```

To perform in-place formatting, use -i option:

```
$ ./lean.py -i specs/S42.dia
```

**Once the modification is done, generate _.dia-cache_ as outlined above.**

#### Tagging

This operation allows to tag Diameter.Msg and Diameter.Avp instances with their corresponding model.

### pcap2pdu.py

#### Arguments

```
$ ./pcap2pdu.py <pcap>
```

**Note that only pcap format is supported. In particular, pcapng and snoop formats are not supported.**

#### Usage

Pcap file is processed using tshark. Pdml stream is analyzed in order to identify Diameter PDUs, which is then decoded using Diameter.Msg.decode function. Handling of IP fragmentation, or transport segmentation is done by tshark. An example of usage is given below:

```
$ ./pcap2pdu.py captures/Cx.pcap | head
# frame 1
Msg(R=True, P=True, code=300, app_id=0x1000000, avps=[
  Avp(code=263, M=True, vendor=0, data='icscf.open-ims.test;457324016;102'),
  Avp(code=264, M=True, vendor=0, data='icscf.open-ims.test'),
  Avp(code=296, M=True, vendor=0, data='open-ims.test'),
  Avp(code=283, M=True, vendor=0, data='open-ims.test'),
  Avp(code=260, M=True, vendor=0, avps=[
    Avp(code=266, M=True, vendor=0, data='\x00\x00(\xaf'),
    Avp(code=258, M=True, vendor=0, data='\x01\x00\x00\x00'),
  ]),
...
```

### pcap2scn.py

#### Arguments

```
$ ./pcap2scn.py [--client <client scenario>] [--server <server scenario>] <pcap>
```

**Note that only pcap format is supported. In particular, pcapng and snoop formats are not supported.**

#### Usage

To generate a Ro client scenario _scenarios/ro-client.scn_ based on a trace _captures/Ro.pcap_:

```
$ ./pcap2scn.py --client scenarios/ro-client.scn captures/Ro.pcap
detected a flow 10.201.9.245:50957 -> 10.201.9.11:3868
anchor ('/code=443/code=444', 'Subscription-Id-Data'), propagating to [(3, True, Avp(code=444, M=True, vendor=0, data='919080000016')), (5, True, Avp(code=444, M=True, vendor=0, data='919080000016'))]
anchor ('/code=283', 'Destination-Realm'), propagating to [(2, False, Avp(code=296, M=True, vendor=0, data='comverse.com')), (3, True, Avp(code=283, M=True, vendor=0, data='comverse.com')), (4, False, Avp(code=296, M=True, vendor=0, data='comverse.com')), (5, True, Avp(code=283, M=True, vendor=0, data='comverse.com')), (6, False, Avp(code=296, M=True, vendor=0, data='comverse.com'))]
...
```

pcap2scn.py will perform the same pcap2pdu.py plus:

- differentiate client and server sides, in order to generate send and receive operations
- detect reused AVP values
- implement copy and paste in subsequent messages

For example, an S6a server must use in the answer the Session-Id value received in the Authentication-Information Request. The reuse is detected by pcap2scn.py, and is implemented in scenario.

The copy operation takes the value from the received Session-Id:

```
  # frame 1
  m = Msg.recv(f)
  assert(m.code == 318)
  assert(m.R)
  tsxs[0] = (m.e2e_id, m.h2h_id)
...
  session_id = m.eval_path('/code=263').data
```
The paste operation is then performed as follows:

```
  # frame 2
  m = Msg(P=True, code=318, app_id=0x1000023, avps=[
    Avp(code=263, M=True, vendor=0, data=session_id),
...
```


### Scenarios

A scenario must contain a run function, which will be given at runtime a stream which can be used to send and receive Diameter messages. The following scenario has been generated using pcap2scn.py:

```
def run(f, args={}):
  tsxs = [()]*3

  # frame 1
  m = Msg(R=True, code=272, app_id=0x4, avps=[
    Avp(code=263, M=True, vendor=0, data='nxl;api;1263278878147'),
...
  ])
  m.send(f)
  tsxs[0] = (m.e2e_id, m.h2h_id) 
  # frame 2
  m = Msg.recv(f)
  assert(m.code == 272)
  assert(not m.R)
  assert(tsxs[0] == (m.e2e_id, m.h2h_id))

  # frame 3
  m = Msg(R=True, code=272, app_id=0x4, avps=[
...
```

### unit.py and fuzz.py

Both programs expect to be run wrapped by `withsctp` utility. Using TCP instead of SCTP is not supported at this time, as the required buffering logic is not implemented yet. `withsctp` utility will transparently make TCP sockets become SCTP sockets. And SCTP sockets are packet oriented and not byte oriented, which explains why TCP requires an additional work.

#### Arguments

```
$ ./unit.py --scenario=<.scn file> --mode=<client|clientloop|server> --local-hostname=<sut.realm> --local-realm=<realm> <target:port>
```

Mode | Behaviour
-----|---------
client | connect to given ip:port and run scenario
clientloop | _forever_(connect to given ip:port and run scenario)
server | bind server on given ip:port, _forever_(accept client connection and run scenario)

```
$ ./fuzz.py --scenario=<.scn file> --mode=<client|server> --local-hostname=<sut.realm> --local-realm=<realm> <target:port>
```

Mode | Behaviour
-----|---------
client | _for each mutation_(connect to given ip:port and run scenario)
server | bind server on given ip:port, _for each mutation_(accept client connection and run scenario)

#### Device-Watchdog handling

Diameter mandates the use of Device-Watchdog Request and Answer to verify connection states. These messages will be used after connection establishment, but they may appear during scenario, at random.

A thin layer will shield user scenario from received Device-Watchdog Request, and will automatically send Device-Watchdog Answer.

The initial behaviour using a SOCK_SEQPACKET AF_UNIX socketpair has been modifed, in order to be more portable. It now uses a SOCK_STREAM AF_UNIX socketpair, with records being delineated via their length. It is implented in two places:

* `scenario.py/pack_frame` and `scenario.py/unpack_frame` which respectively append a 4-byte big-endian of following frame, and conversely.
* `scenario.py/dwr_handler` which automatically replies to received DWR, and forwards other messages to scenario instance.

However answering to DWR requires to set a suitable Origin-Host and Origin-Realm, which is clearly not dependent of the scenario.
`unit.py` and `fuzz.py` both accept to set a local hostname and a local realm. Scenario can access these variables via `local_hostname` and `local_realm`.

#### Fuzzing process

The following pseudocode illustrates how fuzzing is performed:

- the scenario is run once, in order to capture exchanged PDU, and to ensure a single shot runs correctly
- mutations derived from model are computed
- the scenario is run as many time needed in order to test all mutations

```
run scenario once, and collect exchanged messages
tag exchanged messages

for each sent message:
  for each AVP contained in sent message:
    collect mutations based on datatype
    collect mutations based on qualification in context

for each mutation:
  run scenario and execute mutation
```

As a matter of fact, a scenario will generate a bound number of mutations. The behaviour of fuzzing process is deterministic and time needed to perform fuzzing can evaluated prior to start.

During fuzzing, each run may throw exceptions, which will be caught by fuzz.py and processed to keep on fuzzing:

- **socket.timeout**, which is raised by Diameter.Msg.recv when a timeout is specificed. When unspecified, this timeout will be set to 5s.
- **Diameter.RecvMismatch**, which may be raised by scenario when receiving an unexpected message. Scenarios generated by pcap2scn.py will check code and Request flag, and raise this exception if any does not meet the expectations.
