bwlogtools
==========

bwxslogtool.py -- This tool parses sip messages out of the broadworks App Server's XS log

USAGE
=====

usage: bwxslogtool.py [-h] [-p FILENAME] [-m REGEX] [--bwip BWIP] XSLog

currently this tool prints sip logs to STDOUT that match the
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



NOTES
=====

This has been tested on various flavors of linux (Redhat, Ubuntu, SUSE) as well as OSX.  I have not tested on windows, but welcome any feedback.

Unfortunately I had to use a third party library that is not included in the python standard libarary (scapy) so that will need to be included.

I will be maintaining this and adding any features that folks find useful, please report any bugs on github. 
