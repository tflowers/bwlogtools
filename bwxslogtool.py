#!/usr/bin/env python

#----------------------------------------------------------------------------
#THE BEER-WARE LICENSE (Revision 42):
#<tdflowers@gmail.com> wrote this file. As long as you retain this notice you
#can do whatever you want with this stuff. If we meet some day, and you think
#this stuff is worth it, you can buy me a beer in return Tim Flowers
#----------------------------------------------------------------------------


import os.path
import re
import sys
from itertools import groupby
from datetime import datetime
import time
import struct
import socket
import getopt

VERSION=.02

#----------------------------------------------------------------------------
#  Enough people complained about issues with scapy that I decided to roll my 
#  own pcap writing tool... This is a little ugly, but if folks like it,  i'll
#  clean it up ;-)
#----------------------------------------------------------------------------

class Packet(object):
  """
  This is my packet class:  Currently almost everything is hard-coded, and it's EXTREMELY INFLEXABLE.
  this will be cleaned up when I get around to it depending on how well this idea pans out.
  """
  def __init__(self, src='0.0.0.0', dst='0.0.0.0', sport=0, dport=0, data=None):
    self.src = src
    self.dst = dst
    self.sport = sport
    self.dport = dport
    self.data = data

  def udp_header(self):
    ulen = 8 + len(self.data)
    checksum = 0
    return struct.pack('!HHHH', self.sport, self.dport, ulen, checksum)

  def ip_header(self):
    version = 4
    ihl = 5
    ihl_ver = (version << 4) + ihl
    dscp = 0
    tot_len = 20 + len(self.udp_header()) + len(self.data)
    ident = 1
    flags = None
    f_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP

    checksum = 0 #TODO:  FILL THIS IN :)
    saddr = socket.inet_aton(self.src)
    daddr = socket.inet_aton(self.dst)

    ip_header = struct.pack('!BBHHHBBH4s4s', ihl_ver, dscp, tot_len, ident,
                             f_offset, ttl, protocol,  checksum, saddr, daddr)

    checksum = self.checksum(ip_header)
    ip_header = list(ip_header)
    ip_header[10:12] = checksum
    return "".join(ip_header)

  def checksum(self, data):
    l = len(data)
    s = 0
    for i in range(0, l, 2):
      part = data[i:i+2]
      val = int(part.encode('hex'), 16)
      s = (s + val) % 0xFFFF
    s = ~s & 0xFFFF
    return struct.pack('>H', s)

  def __repr__(self):
    return str(self.ip_header() + self.udp_header() + self.data)



class PcapWriter(object):
  def __init__(self, filename, network=101 ):
    """
    initialize the pcap writer, and write the libpcap header to the file
    Used the following documentation to create this:
    http://wiki.wireshark.org/Development/LibpcapFileFormat
    """
    self.magic_number = 0xa1b2c3d4L
    self.version_major = 2 # versoin 2.4
    self.version_minor = 4 # version 2.4
    self.thiszone = 0
    self.sigfigs = 0
    self.snaplen = 65535
    self.network = network #Link Layer Type (default 101)
    self.pcap_header = struct.pack('@IHHIIII', self.magic_number,
                                   self.version_major, self.version_minor,
                                   self.thiszone, self.sigfigs, self.snaplen,
                                   self.network)
    self.f = open(filename, 'wb')

    self.f.write(self.pcap_header)

  def close(self):
    self.f.close()

  def write(self, pkt, ts=None):
    """
    Writes single binarary packet to pcap file,
    Used the following documentation to create this:
    should probably be called something like this for list of packets

    map(write, packets)

    or

    for packet in packets:
      write(packet)

    If there is a timestamp it should be in sec.usec format ;-),
    and it can be passed as an optional parameter

    http://wiki.wireshark.org/Development/LibpcapFileFormat
    """
    incl_len = len(pkt)
    orig_len = incl_len

    if not ts:
      ts = time.time()
    ts_sec = int(ts)
    ts_usec = int(((ts)-ts_sec)*1000000)
    packet_header = struct.pack('@IIII', ts_sec, ts_usec, incl_len, orig_len)
    self.f.write(packet_header)
    self.f.write(pkt)

  def __del__(self):
    self.f.close()

class XSLogEntry(object):
  _siplogfmt = re.compile(r'^(?:udp|tcp)(?:\ )'
                          +'(?:[0-9]+\ Bytes\ )' 
                          +'(?P<direction>IN|OUT)(?:\ )'
                          +'(?:to|from)(?:\ )'
                          +'(?:(?P<ipaddr>.*)(?::)(?P<port>.*)\r\n)'
                          +'(?P<sipmsg>(?:.*\r\n)+)', re.M)

  _timestampfmt = re.compile(r'(?P<year>[0-9]{4})(?:\.)'
                             +'(?P<month>[0-9]{2})(?:\.)'
                             +'(?P<day>[0-9]{2})(?:\ )'
                             +'(?P<hour>[0-9]{2})(?::)'
                             +'(?P<min>[0-9]{2})(?::)'
                             +'(?P<sec>[0-9]{2})\:'
                             +'(?P<msec>[0-9]{3})(?:\ )'
                             +'(?P<tz>[A-Z]{3})$')

  def __init__(self, datetime=None, loglevel=None, logtype=None, body=None):
    self.datetime = self.convert_timestamp(datetime)
    self.loglevel = loglevel
    self.logtype = logtype
    self.body = body

  def __repr__(self):
    line = ''
    for x in range(80):
      line += '-'
    line += '\n'
    repr_str = '\n' + line + str(self.datetime)
    repr_str += " " + self.loglevel + " " + self.logtype + ":" + "\n"
    repr_str += line + "\n" + self.body

    return repr_str
    

  def type(self):
    return self.__class__.__name__

  def convert_timestamp(self, timestr):
    match = self._timestampfmt.match(timestr)
    if not match:
      return False
    ts = match.groupdict()
    #convert timestamp entries to int HACK
    for key in ts:
      if key != 'tz':
        ts[key] = int(ts[key])
    return datetime(ts['year'], ts['month'], ts['day'], 
                    ts['hour'], ts['min'], ts['sec'], 
                    ts['msec'] * 1000 )
  
  @staticmethod
  def factory(rawlog):
    logline, body = rawlog
    entries = [entry.strip() for entry in logline.split('|')]
    datetime, loglevel, logtype = entries[:3]
    match = XSLogEntry._siplogfmt.match(body)
    if match: 
      return SipXSLogEntry(datetime, loglevel, logtype, body, match.groupdict())
    else: 
      return GenericXSLogEntry(datetime, loglevel, logtype, body)


class SipXSLogEntry(XSLogEntry):

  def __init__(self, datetime=None, loglevel=None, 
               logtype=None, body=None, siplog=None):
    super(SipXSLogEntry, self).__init__(datetime, loglevel, logtype, body)
    self.sipmsg = siplog['sipmsg'] + "\r\n"
    self.direction = siplog['direction']
    self.ipaddr = siplog['ipaddr']
    self.port = siplog['port']


class GenericXSLogEntry(XSLogEntry):

  def __init__(self, datetime=None, loglevel=None, logtype=None, body=None):
    super(GenericXSLogEntry, self).__init__(datetime, loglevel, logtype, body)

class XSLog(object):
  """
  XSLog  Parses Broadworks XSLog files into a list of logs
  """

  _logstart = re.compile(r'^[0-9]{4}\.[0-9]{2}\.[0-9]{2}')

  def __init__(self, fn):
    self.logs = self.parser(fn)

  def __iter__(self):
    for log in self.logs:
      yield log

  def __getitem__(self, key):
    return self.logs[key]

  def siplogs(self, regex=None):
    siplogs = [log for log in self.logs if log.type() == 'SipXSLogEntry']
    if not regex: 
      return siplogs
    else:
      return [siplog for siplog in siplogs if regex in siplog.sipmsg or re.match(regex, siplog.sipmsg)]

  def to_pcap(self, filename, bwServerIp = '0.0.0.0', bwServerPort = 5060, siplogs = None):
    if not siplogs:
      siplogs = self.siplogs()
    plist = []
    pw = PcapWriter(filename)
    for siplog in siplogs:
      dt = siplog.datetime
      if siplog.direction == 'IN':
        saddr, sport = siplog.ipaddr, int(siplog.port)
        daddr, dport = bwServerIp, bwServerPort
      else:
        saddr, sport = bwServerIp, bwServerPort
        daddr, dport = siplog.ipaddr, int(siplog.port)
      ts = float(str(dt.strftime("%s")) + '.' + str(dt.microsecond))
      pkt = Packet(saddr, daddr, sport, dport, siplog.sipmsg)
      pw.write(str(pkt), ts)
    pw.close()

  def parser(self, fn):
    groups = []
    keys = []
    try:
      f = open(fn, 'r')
      tmp = f.next()
      while not self._logstart.match(tmp):
        tmp = f.next()
      keys.append(tmp)
      for key, group in groupby(f, self._logstart.match):
        if key: keys.append(list(group))
        else: groups.append(list(group))
    finally:
      f.close()
    #This assumes that the parser gets a group entry for each key,
    #this may be error prone, but so far seems to work.
    keys = ["".join(k).strip() for k in keys]
    groups = ["".join(g).strip() for g in groups]
    rawlogs =  zip(keys, groups)
    return [XSLogEntry.factory(rl) for rl in rawlogs]



def usage():
  usage_str = """
usage: arg.py [-h] [-p FILENAME] [-m REGEX] [--bwip BWIP] XSLog

bwXSLog tool, currently this tool prints sip logs to STDOUT that match the
pattern defined in the -m option, or if -p is specified it will print the sip
messages to the specified pcap file

positional arguments:
  XSLog                 XSLog to parse

optional arguments:
  -h, --help            show this help message and exit
  -p FILENAME, --pcap FILENAME
                        PCAP file to write logs to.
  -m REGEX, --match REGEX
                        Pattern to match
  --bwip BWIP           ip address of the broadworks server to be used when
                        writing to pcap files

"""
  print(usage_str)


def parse_argv():

  arg_dict = {}
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hp:m:",
                          ["pcap=", "match=", "bwip="])
  except getopt.GetoptError:
    print("Error parsing command line options:")
    usage()
    sys.exit()

  for o, a in opts:
    if o == "-h":
      usage()
      sys.exit()
    elif o in ("-p", "--pcap"):
      arg_dict['pcap'] = a
    elif o in ("-m", "--match"):
      arg_dict['match'] = a
    elif o == "--bwip":
      arg_dict['bwip'] = a
    else:
      assert False, "unhandled option"

  if len(args) != 1:
    print("Error: XSLog not specified!")
    usage()
    sys.exit()

  arg_dict['XSLog'] = args[0]
  return arg_dict




def main(argv):
  args = parse_argv()
  
  if not os.path.isfile(args['XSLog']): 
    print("ERROR:  Cannot open XSLog: %s" % args['XSLog'])
    usage()
    sys.exit()

  try:
    xslog = XSLog(str(args['XSLog']))
  except:
    print("ERROR: unable to parse XSLog: %s" % args['XSLog'])
    sys.exit()

  if 'match' in args:
    siplogs = xslog.siplogs(args['match'])
  else:
    siplogs = xslog.siplogs()

  if 'pcap' in args:
    if 'bwip' in args: xslog.to_pcap(args['pcap'], args['bwip'], siplogs=siplogs)
    else: xslog.to_pcap(args['pcap'], siplogs=siplogs)
  else:
    for log in siplogs:
      print log


if __name__ == '__main__':
  main(sys.argv)
