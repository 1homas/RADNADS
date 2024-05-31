#!/usr/bin/env python3
"""
A `radnad` Python wrapper that performs RADIUS authentication(s).
For details about `radnad`, see https://wiki.freeradius.org/config/Radclient

Usage:
    radnad.py
    radnad.py --help

    radnad.py mab                    # attempt MAB wired auth with a random MAC address
    radnad.py mab-wired              # MAB wired auth with a random MAC address
    radnad.py mab-wired --calling 1234567890ab
    radnad.py mab-wireless --called 11:22:33:44:55:66:iot
    radnad.py mab-wireless --calling 1234567890ab --called 11:22:33:44:55:66:iot

    radnad.py dot1x -u thomas -p C1sco12345    # 'dot1x' defaults to wired
    radnad.py dot1x -u meraki_8021x_test -p C1sco12345 --calling 02:00:00:00:00:01
    radnad.py dot1x-wired -u thomas -p C1sco12345

    radnad.py dot1x-wireless -u thomas -p C1sco12345
    radnad.py dot1x-wireless -u thomas -p C1sco12345 --called 11:22:33:44:55:66:corp
    radnad.py dot1x-wireless -u employee -p C1sco12345 --called 11:22:33:44:55:66:corp

    radnad.py vpn -u thomas -p C1sco12345

    radnad.py sessions               # list all active sessions

    radnad.py stop                   # stop all active sessions
    radnad.py stop --sid 35          # stop session ID == 35


Requires setting the these environment variables using the `export` command:
  export ISE_PSN='1.2.3.4'              # hostname or IP of an ISE PSN (policy service node)
  export ISE_RADIUS_SECRET='C1sco12345' # RADIUS server pre-shared key

You may add these export lines to a text file and load with `source`:
  source ise-env.sh

"""
__author__ = "Thomas Howard"
__email__ = "thomas@cisco.com"
__license__ = "MIT - https://mit-license.org/"

from enum import Enum
from multidict import MultiDict
import argparse
import asyncio
import csv
import datetime
import io
import logging
import os
import random
import pandas as pd
import sys
import tabulate
import time
import yaml
import traceback
import tracemalloc
tracemalloc.start()

LOG_FORMAT = '%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s'
logging.basicConfig(filename='radnad.log', format=LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S", encoding='utf-8', level=logging.DEBUG) # log to stdout by default
log = logging.getLogger('radnad')
log.setLevel(logging.WARNING)


class RADIUSResponse():
    """
    An object representing a RADIUS response.

    📄 RFC2866:
      - The Attributes field MAY have one or more Reply-Message attributes
      - The Attributes field MAY have a single State Attribute, or none.
      - Vendor-Specific, Idle-Timeout, Session-Timeout and Proxy-State attributes MAY also be included.  
      - A RADIUS client MAY ignore Attributes with an unknown Type.
    """

    # RADIUS Request/Response Packet Types
    ACCESS_REQUEST = 'Access-Request'           # 1
    ACCESS_ACCEPT = 'Access-Accept'             # 2
    ACCESS_REJECT = 'Access-Reject'             # 3
    ACCOUNTING_REQUEST = 'Accounting-Request'   # 4
    ACCOUNTING_RESPONSE = 'Accounting-Response' # 5
    ACCESS_CHALLENGE = 'Access-Challenge'       # 11

    # Types list for testing membership
    RSP_TYPES = [
        ACCESS_ACCEPT,
        ACCESS_REJECT,
        ACCOUNTING_REQUEST,
        ACCOUNTING_RESPONSE,
        ACCESS_CHALLENGE
    ]


    def __init__(self, content:str=None) -> None:
        """
        Instantiates the RADIUSResponse object from the specified radnad content.

        - content (str): the `radnad` output
        - raises TimeoutError

        Example Access-Accept Output:
        Sent Access-Request Id 192 from 0.0.0.0:fd98 to 1.2.3.4:1812 length 59
        	User-Name = "ahoward"
        	User-Password = "C1sco12345"
        	Service-Type = Framed
        	NAS-Port-Type = Ethernet
        	Cleartext-Password = "C1sco12345"
        Received Access-Accept Id 192 from 1.2.3.4:714 to 10.16.51.114:64920 length 106
        	User-Name = "ahoward"
        	Class = 0x434143533a6336313238353162435430705452444f634c4e724933665a6263594f475079722f527463303237424756363451573550307a4d3a4953452f3438383037313031332f31303430

        Example Access-Reject Output:
        Sent Access-Request Id 107 from 0.0.0.0:d618 to 1.2.3.4:1812 length 58
            User-Name = "bjones"
            User-Password = "C1sco12345"
            Service-Type = Framed
            NAS-Port-Type = Ethernet
            Cleartext-Password = "C1sco12345"
        Received Access-Reject Id 107 from 1.2.3.4:714 to 10.16.92.65:54808 length 20

        Example Timeout Output:
        (0) No reply from server for ID 124 socket 4
        """

        self.content = None 
        self.timestamp:int = 0 #
        self.id:int = 0 # the request ID
        self.req_type:str = None
        self.req_length:int = 0
        self.req_attrs:MultiDict = MultiDict() # 💡 Required to support multiple entries of same key name
        self.rsp_type:str = None # one of RSP_TYPES
        self.rsp_length:int = 0
        self.rsp_attrs:MultiDict = MultiDict() # 💡 Required to support multiple entries of same key name
        self.nas_ip:str = None # the NAS (simulator) IP address of in the request
        self.nas_port:int = 0 # the NAS (simulator) port in the request
        self.srv_ip:str = None # the RADIUS server IP address in the request
        self.srv_port:int = 0 # the RADIUS server port in the request

        if content is None: raise ValueError('content is None')
        # 💡 ToDo: create from response?
        self.timestamp = time.time() # time of response creation - naive timestamp?
        self.content = content # original radnad CLI output

        # 🚧 ToDo: Handle Drop/Timeout better!
        # Example: (0) No reply from server for ID 124 socket 4
        if content.find('Received') <= 0:
            # log.error(f"▷ RADIUSResponse.content: No Reply. Timeout/Dropped: {content}")
            # raise TimeoutError(f"No Reply. Timeout/Dropped:\n{content}")
            raise TimeoutError(content)

        # Parse Sent section: 
        # Sent Access-Request Id 192 from 0.0.0.0:fd98 to 1.2.3.4:1812 length 59
        lines = content.splitlines()   # process each line
        line = lines.pop(0) 
        [_Sent, self.req_type, _id, self.id, _from, nas, _to, server, _length, self.req_length] = line.split(' ')
        self.nas_ip, self.nas_port = nas.split(':')
        self.srv_ip, self.srv_port = server.split(':')
        while line:= lines.pop(0):
            if line.find('=') <= 0: break                        # No '=' means no attribute=value pair and starts the Received section
            key,val = line.strip().split('=', maxsplit=1)         # 💡 Only split first `=` to avoid splitting VSAs! (Cisco-AVPair = "profile-name=Unknown")
            self.req_attrs[key.strip('"\' ')] = val.strip('"\' ') # 💡 Remove any spaces and double-quotes before adding!

        # Parse Received section. 
        # Variables prefixed with `_` are template placeholders to discard.
        # Example: 
        # Received Access-Accept Id 192 from 1.2.3.4:714 to 10.16.51.114:64920 length 106
        [_Received, self.rsp_type, _id, self.id, _from, server, _to, nas, _length, self.rsp_length] = line.split(' ')
        self.nas_ip, self.nas_port = nas.split(':')
        self.srv_ip, self.srv_port = server.split(':')
        if self.rsp_type not in self.RSP_TYPES: raise ValueError(f"No such RSP_TYPES: {self.rsp_type}")
        while len(lines) > 0:  # Access-Reject has no attributes!
            line = lines.pop(0)
            key,val = line.strip().split('=', maxsplit=1)         # 💡 Only split first `=`! Careful with `Cisco-AVPair = "profile-name=Unknown"``
            self.rsp_attrs[key.strip('"\' ')] = val.strip('"\' ') # 💡 Remove any spaces and double-quotes before adding!

        # redact passwords
        if 'User-Password' in self.req_attrs:
            self.req_attrs['User-Password'] = len(self.req_attrs['User-Password']) * '*'
        if 'Cleartext-Password' in self.req_attrs:
            self.req_attrs['Cleartext-Password'] = len(self.req_attrs['Cleartext-Password']) * '*'

        # 📄 RFC2866: MAY include one or more Reply-Message attributes which the NAS MAY display to the user.
        for msg in self.rsp_attrs.getall('Reply-Message', ''):
            print(f"Reply-Message: {msg}", file=sys.stdout)


    @classmethod
    def avps_to_multidict(self, text:str=None) -> dict:
        """
        Returns a multidict represented by the "attribute = value" pairs(AVPs) in the text.
        - text (str): a line of `radnad` RADIUS attribute-value pairs.

        Example input text:
          Sent Access-Request Id 192 from 0.0.0.0:fd98 to 1.2.3.4:1812 length 59
            User-Name = "thomas"
            User-Password = "C1sco12345"
            Service-Type = Framed
            NAS-Port-Type = Ethernet
            Cisco-AVPair = "profile-name=Unknown"
        """
        mdict = MultiDict()
        for line in text.splitlines():
            if line.find('=') <= 0: continue               # No attribute=value pair!
            key,val = line.strip().split('=', maxsplit=1)   # 💡 Only split first `=`! (Cisco-AVPair = "profile-name=Unknown")
            mdict[key.strip('"\' ')] = val.strip('"\' ')    # 💡 Remove any spaces and double-quotes before adding!
        return mdict


    def __repr__(self) -> str:
        """
        RADIUSResponse class representation.
        """
        out = io.StringIO()
        print(f"__repr__ <RADIUSResponse({datetime.datetime.fromtimestamp(self.timestamp).isoformat(sep=' ', timespec='milliseconds')}, {self.content}, {self.req_attrs}, {self.rsp_attrs}>", file=out,)
        return out.getvalue()


    def __str__(self) -> str:
        """
        Re-create the radnad request+response output.
        """
        return self.to_radclient_log()


    def is_auth(self) -> bool:
        """
        Returns True if this RADIUS response is for an authentication request.
        """
        return self.req_type == RADIUSResponse.ACCESS_REQUEST


    def is_passed(self) -> bool:
        """
        Returns True if this RADIUS response is for an authentication request and it was accepted by the RADIUS server.
        """
        return self.req_type == RADIUSResponse.ACCESS_REQUEST and self.rsp_type == RADIUSResponse.ACCESS_ACCEPT


    def is_failed(self) -> bool:
        """
        Returns True if this RADIUS response is for an authentication request and it was accepted by the RADIUS server.
        """
        return self.req_type == RADIUSResponse.ACCESS_REQUEST and self.rsp_type == RADIUSResponse.ACCESS_REJECT


    def is_acct(self) -> bool:
        """
        Returns True if this RADIUS response is for an accounting request.
        """
        return self.req_type == RADIUSResponse.ACCOUNTING_REQUEST


    def is_accepted(self) -> bool:
        """
        Returns True if this RADIUS response is for an accounting request and has been accepted by the RADIUS server.
        """
        return self.req_type == RADIUSResponse.ACCOUNTING_REQUEST and self.rsp_type == RADIUSResponse.ACCOUNTING_RESPONSE


    def guess_access_method(self) -> str:
        if self.req_attrs.get('Service-Type', None) == 'Call-Check': return 'MAB'
        if self.req_attrs.get('Service-Type', None) == 'Framed-User': return '802.1X'
        if self.req_attrs.get('NAS-Port-Type', None) == 'Virtual': return 'VPN'

        # Report any unknown access methods
        print(f"guess_access_method() Unknown: {self.req_attrs.get('Service-Type', None)} {self.req_attrs.get('NAS-Port-Type', None)}", file=sys.stderr)
        return 'Unknown'


    def to_radclient_log(self) -> str:
        """
        Return the radnad representation of the request+response output.

        Example Access-Accept Output:
            Sent Access-Request Id 192 from 0.0.0.0:fd98 to 1.2.3.4:1812 length 59
                User-Name = "ahoward"
                User-Password = "C1sco12345"
                Service-Type = Framed
                NAS-Port-Type = Ethernet
                Cleartext-Password = "C1sco12345"
            Received Access-Accept Id 192 from 1.2.3.4:714 to 10.16.51.114:64920 length 106
                User-Name = "ahoward"
                Class = 0x434143533a6336313238353162435430705452444f634c4e724933665a6263594f475079722f527463303237424756363451573550307a4d3a4953452f3438383037313031332f31303430

        Example Access-Reject Output:
            Sent Access-Request Id 107 from 0.0.0.0:d618 to 1.2.3.4:1812 length 58
                User-Name = "bjones"
                User-Password = "C1sco12345"
                Service-Type = Framed
                NAS-Port-Type = Ethernet
                Cleartext-Password = "C1sco12345"
            Received Access-Reject Id 107 from 1.2.3.4:714 to 10.16.92.65:54808 length 20

        Example Timeout Output:
            (0) No reply from server for ID 124 socket 4
        """

        # 🚧 ToDo: Handle the Timeout output.

        INDENT = ' ' * 4
        out = io.StringIO()
        print(f"Sent {self.req_type} Id {self.id} from {self.nas_ip}:{self.nas_port} to {self.srv_ip}:{self.srv_port} length {self.req_length}", file=out)
        print(f"{INDENT}",f"\n{INDENT}".join([f"{key}='{val}'" for key,val in self.req_attrs.items()]), sep="", file=out)
        print(f"Received {self.rsp_type} Id {self.id} from {self.srv_ip}:{self.srv_port} to {self.nas_ip}:{self.nas_port} length {self.rsp_length}", file=out)
        print(f"{INDENT}", f"\n{INDENT}".join([f"{key}='{val}'" for key,val in self.rsp_attrs.items()]), sep="", file=out)
        return out.getvalue()


    def to_ise_log(self) -> str:
        """
        Generate a log string *similar* to an ISE LiveLog entry. 
        Not all values are available in the RADIUS client and the order and format may be customized.

        ISE LiveLog Field Names:
            'Timestamp',                # ISE format example: Jan 01, 2024 01:02:03.456 PM
            'Event',                    # Pass, Fail, Start, Stop
            'Identity',                 # username or MAC (12:34:56:78:90:AB)
            'Endpoint',                 # MAC (12:34:56:78:90:AB)
            'Method',                   # 'mab', ...
            'NAS-Id',                   # RADIUS client name in ISE (should match NAD-Identifier)
            'NAS-Port-Type',            # RADIUS client port, if any
            'NAS-Port-Id',              # RADIUS client port, if any
            'NAS-IP-Address',           # Endpoint IP address, if provided by RADIUS client
            'Acct-Session-Id',          # Created by RADIUS client
            'CiscoAVPair',              # If assigned by ISE
            # 'Security Group',         # If assigned by ISE
            # 'Endpoint Profile',       # Unknown unless returned in attribute!
            # 'Server',                 # ISE PSN node name
            # 'Response Time (ms)',     # Example: 29
        """
        log = {
            'Timestamp'   : datetime.datetime.fromtimestamp(self.timestamp, tz=None).isoformat(sep=" ", timespec="milliseconds"),
            'Event'       : self.RESPONSE_ICONS[self.rsp_type],  # Passed, Failed, Session
            'Identity'    : self.req_attrs.get('User-Name', ''),
            'Endpoint'    : self.req_attrs.get('Calling-Station-Id', ''),
            'Endpoin IP' : self.req_attrs.get('Framed-IP-Address', ''),
            'Method'      : self.guess_access_method(),
            'NAS-Id'      : self.req_attrs.get('NAS-Identifier', ''),
            'NAS-IP' : self.req_attrs.get('NAS-IP-Address', ''),
            'Port-Type' : self.req_attrs.get('NAS-Port-Type', ''),
            'Port-Id' : self.req_attrs.get('NAS-Port-Id', ''),
            'Acct-Session-Id'  : self.req_attrs.get('Acct-Session-Id', ''),
            # 'Attributes'  : RADNAD.to_avp_string(self.req_attrs),
        }
        out = io.StringIO()
        print(tabulate.tabulate([log.keys(), log.values()], headers="firstrow", tablefmt="simple"), file=out)
        return out.getvalue()




class RADNAD:
    """
    A `radnad` Python wrapper that performs RADIUS authentication(s).
    For details about `radnad`, see https://wiki.freeradius.org/config/Radclient
    """

    # Class variables
    AUTH_PORT_DEFAULT = 1812
    ACCT_PORT_DEFAULT = 1813
    COA_PORT_DEFAULT = 1700

    ACCT_START = 'Start'
    ACCT_STOP = 'Stop'

    HIDE_COLUMNS = ['Class','Other']

    RETRIES_DEFAULT = 3 
    RETRIES_MIN = 0 
    RETRIES_MAX = 10 

    SESSION_TIMEOUT = 3600 # seconds
    TIMEOUT_DEFAULT = 5 # seconds
    TIMEOUT_MIN = 1 # seconds
    TIMEOUT_MAX = 60 # seconds
    LOG_MIN = 0
    LOG_MAX = 5

    COMMAND_DEFAULT = 'auth'
    OPTIONS_DEFAULT = '-x' # show attributes sent and received
    NAS_IDENTIFIER_DEFAULT = 'RADNAD'

    NAS_PORT_TYPES = [
        # NAS-Port-Type convenience list
        # Type of physical port of the NAS authenticating the user.
        # It can be used instead of or in addition to the NAS-Port (5) attribute.
        # It is only used in Access-Request packets.
        # NAS-Port (5) or NAS-Port-Type or both SHOULD be present in an Access-Request packet.
        'Async', # ( 0) 
        'Sync', # ( 1) 
        'ISDN-Sync', # ( 2) ISDN Sync
        'ISDN-Async-V.120', # ( 3) ISDN Async V.120
        'ISDN-Async-V.110', # ( 4) ISDN Async V.110
        'Virtual', # ( 5) Use this for VPN
        'PIAFS', # ( 6) 
        'HDLC-Clear-Channel', # ( 7) HDLC Clear Channel
        'X.25', # ( 8) 
        'X.75', # ( 9) 
        'G.3-Fax', # (10) G.3 Fax
        'SDSL', # (11) Symmetric DSL
        'ADSL-CAP', # (12) Asymmetric DSL, Carrierless Amplitude Phase Modulation
        'ADSL-DMT', # (13) Asymmetric DSL, Discrete Multi-Tone
        'IDSL', # (14) ISDN Digital Subscriber Line
        'Ethernet', # (15) Ethernet (wired)
        'xDSL', # (16)  - Digital Subscriber Line of unknown type
        'Cable', # (17) 
        'Wireless-Other', # (18) Wireless - Other
        'Wireless-802.11', # (19) Wireless - IEEE 802.11
    ]

    # How the session was terminated; Only in Accounting-Request with Acct-Status-Type == Stop.
    # 'Acct-Terminate-Cause'
    ACCT_TERMINATE_CAUSES = [
        'User Request'       ,  #  1 : User requested termination of service by logging out
        'Lost Carrier'       ,  #  2 : DCD was dropped on the port
        'Lost Service'       ,  #  3 : Service can no longer be provided; for example, user's connection to a host was interrupted
        'Idle Timeout'       ,  #  4 : Idle timer expired
        'Session Timeout'    ,  #  5 : Maximum session length timer expired
        'Admin Reset'        ,  #  6 : Administrator reset the port or session
        'Admin Reboot'       ,  #  7 : Administrator is ending service on the NAS to reboot device
        'Port Error'         ,  #  8 : NAS detected an error on the port which required ending the session
        'NAS Error'          ,  #  9 : NAS detected some error (other than on the port) which required ending the session
        'NAS Request'        ,  # 10 : NAS ended session for a non-error reason not otherwise listed here
        'NAS Reboot'         ,  # 11 : The NAS ended the session in order to reboot non-administratively ("crash")
        'Port Unneeded'      ,  # 12 : NAS ended session because resource usage fell below low-water mark
        'Port Preempted'     ,  # 13 : NAS ended session in order to allocate the port to a higher priority use
        'Port Suspended'     ,  # 14 : NAS ended session to suspend a virtual session
        'Service Unavailable',  # 15 : NAS was unable to provide requested service
        'Callback'           ,  # 16 : NAS is terminating current session in order to perform callback for a new session
        'User Error'         ,  # 17 : Input from user is in error, causing termination of session
        'Host Request'       ,  # 18 : Login Host terminated session normally
    ]

    SESSIONS_FILENAME = 'radnad.sessions.csv'
    SESSION_COLUMNS = [
        'Timestamp',           # timestamp of the transaction
        'Method',              # authentication method name: [802.1X, MAB, VPN, etc.]
        'Status',              # RADIUS accounting state [Start,Stop]
        'User-Name',           # Username or endpoint name (MAB)
        'Calling-Station-Id',  # Endpoint MAC address (IP for VPN)
        'Framed-IP-Address',   # endpoint IP address
        'Session-Timeout',     # in seconds
        'Acct-Session-Id',     # accounting session ID
        'Called-Station-Id',   # network device MAC
        'NAS-Port-Type',       # type of port used. See NAS_PORT_TYPES
        'NAS-Port-Id',         # String identifying the port (GigabitEthernet1/1)
        'NAS-Port',            # numeric port on which the session is terminated
        'NAS-Identifier',      # name given to this network device
        'Class',               # class value from AAA server, if any
        'Other',               # Other attributes
    ]

    ICONS = {
        # name : icon       # alternatives
        'ACCT' : '𝍖',
        'AUTH' : '⛿',
        'BUG' : '🐞',
        'CACHE': '↯', # ⧉
        'CHALLENGE' : '⨁',
        'COA' : 'Δ',
        'CONNECT' : '║',
        'DISCONNECT' : '╫',
        'DOT1X' : '🇽',
        'ENDPOINT' : '✺',
        'EVENT': '⊛',
        'ERROR' : '✖',
        'FAIL' : '✖',
        'INFO' : 'ⓘ', # i
        'KEY' : '⚿', 
        'MAB' : 'Ⓜ',
        'MISSING': '👻',
        'NAD' : '目',
        'NEW': '🌟',
        'PASS' : '✔',
        'SERVER' : '目',
        'SESSION' : '⎆',
        'START': '▷',
        'STOP' : '□',
        'TIMEOUT' : '⏱',
        'TODO'  : '🚧',
        'TOKEN' : '⎔',
        'USER'  : '👤',
        'WARN'  : '⚠',
        'WIRED' : '🜷',
        'WIRELESS' : '⟪',
        'PLAY' : '▶',
        'STOP' : '■',
        'PAUSE': '⏸',
        'WAIT' : '⏱',
        'UNKNOWN' : '❓',
    }

    RESPONSE_ICONS = {
        RADIUSResponse.ACCESS_ACCEPT: ICONS['PASS'],
        RADIUSResponse.ACCESS_REJECT: ICONS['FAIL'],
        RADIUSResponse.ACCOUNTING_RESPONSE: ICONS['SESSION'],
        RADIUSResponse.ACCESS_CHALLENGE: ICONS['CHALLENGE'],
    }

    def __init__(self,
                  name:str=NAS_IDENTIFIER_DEFAULT,
                  server:str=None,
                  secret:str=None,
                  auth_port:int=AUTH_PORT_DEFAULT,
                  acct_port:int=ACCT_PORT_DEFAULT,
                  coa_port:int=COA_PORT_DEFAULT,
                  options:str=OPTIONS_DEFAULT,
                  retries:int=RETRIES_DEFAULT,  # If timeout, retry sending packet N times
                  timeout:int=TIMEOUT_DEFAULT,  # seconds
                  level:int=0,  # verbosity log level
                 ):
        """
        Creates a RADNAD instance with the spcecific configuration options.

        name (str): the NAS identifier to use for RADIUS client requests. Default: `NAS_IDENTIFIER_DEFAULT`
        server (str): the RADIUS server address to send requests. Default: None
        secret (str): the RADIUS pre-shared key to use with the server. Default: None
        auth_port (int): the RADIUS authentication port. Default: `AUTH_PORT_DEFAULT`
        acct_port (int): the RADIUS accounting port. Default: `ACCT_PORT_DEFAULT`
        coa_port (int): the RADIUS change of authorization (COA) port. Default: `COA_PORT_DEFAULT`
        options (str): radnad options string. Default: `OPTIONS_DEFAULT`
        retries (int): the number of retries before timeout. Default: `RETRIES_DEFAULT`,
        timeout (int): the time to wait, in seconds, between retries. Default: `TIMEOUT_DEFAULT`,
        level (int): verbosity (log) level (0-5). Default: 0
        """
        log.debug(f"▷ RADNAD.__init__(name:{name}, server:{server}, auth_port:{auth_port}, acct_port:{acct_port}, coa_port:{coa_port}, secret:{'*'}, options:{options}, retries:{retries}, timeout:{timeout})")

        # Instance Variables
        self.name = name                          # NAS-Identifier
        self.server = None                        # RADIUS server hostname or IP address
        self.secret = None                        # RADIUS shared secret. 📄 RFC2866: The source IP of the Access-Request packet MUST be used to select the shared secret.
        self.auth_port = self.AUTH_PORT_DEFAULT   # RADIUS authentication port
        self.acct_port = self.ACCT_PORT_DEFAULT   # RADIUS accounting port
        self.coa_port = self.COA_PORT_DEFAULT     # RADIUS Change of Authorization (CoA) port
        self.options = self.OPTIONS_DEFAULT       # `radclient` options
        self.timeout = self.TIMEOUT_DEFAULT       # time, in seconds, before retry
        self.retries = self.RETRIES_DEFAULT       # total number of retries after timeouts
        self.logger = None                        # logger 🚧 ToDo: Implement this!
        self.sessions = None                      # sessions (accounting) DataFrame
        self.counter = 0                          # session counter
        self.level = 0                            # log level

        if server is None or server == '': raise ValueError(f"Must specify a RADIUS server name or address")
        if not isinstance(server, str): raise ValueError(f"server {server} is a {type(server)} not a string")
        self.server = server
        
        if int(auth_port) < 1024 or int(auth_port) > 65536: raise ValueError(f"Invalid port number: {auth_port}")
        self.auth_port = auth_port

        if int(acct_port) < 1024 or int(acct_port) > 65536: raise ValueError(f"Invalid port number: {acct_port}")
        self.acct_port = acct_port
        self.coa_port = coa_port

        if secret is None or secret == '': raise ValueError(f"Must specify a secret")
        self.secret = secret

        # 🚧 ToDo: perform a server test?

        if options is None or options == '': options = self.OPTIONS_DEFAULT
        if options.find('x') < 0: raise ValueError(f"Option x required")
        self.options = options

        if retries < self.RETRIES_MIN or retries > self.RETRIES_MAX: raise ValueError(f"Invalid retries: {retries}")
        self.retries = retries

        if timeout < self.TIMEOUT_MIN or timeout > self.TIMEOUT_MAX: raise ValueError(f"Invalid timeout: {timeout}")
        self.timeout = timeout

        if level < self.LOG_MIN or timeout > self.LOG_MAX: raise ValueError(f"Invalid verbosity/log level: {level}")
        self.level = level

        # Load existing sessions CSV file
        if os.path.exists(self.SESSIONS_FILENAME):
            self.sessions = pd.read_csv(self.SESSIONS_FILENAME, parse_dates=True, index_col=[self.SESSION_COLUMNS[0]]).fillna('')
            self.counter = 0 if len(self.sessions) == 0 else self.sessions['Acct-Session-Id'].max()
            log.info(f"{RADNAD.ICONS['INFO']} Loaded {len(self.sessions)} Sessions, Last Acct-Session-Id: {self.counter}")
        else:
            # No CSV, create a new DataFrame
            self.sessions = pd.DataFrame(columns=self.SESSION_COLUMNS)
            self.sessions.set_index([self.SESSION_COLUMNS[0]], inplace=True)
            self.sessions.index = pd.to_datetime(self.sessions.index)
            

    def _handle_exception(self, e:Exception=None) -> None:
        """
        """
        tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
        print(f"{self.ICONS['ERROR']} RADNAD: {e.__class__} | {tb_text}", file=sys.stderr)


    def __del__(self) -> None:
        """
        Close the RADNAD by persisting any sessions' state.
        """
        self.sessions.to_csv(self.SESSIONS_FILENAME, index=True)


    def generate_session_id(self) -> str:
        """
        A string representing a unique session ID for RADIUS Accounting.
        This is a random number implementation.
        🚧 ToDo: Implement as a Python generator reading from a persistent session file

        From https://datatracker.ietf.org/doc/html/rfc2866
        The start and stop records for a given session MUST have the same Acct-Session-Id.
        An Accounting-Request packet MUST have an Acct-Session-Id.
        An Access-Request packet MAY have an Acct-Session-Id; if it does, then the NAS MUST use the same Acct-Session-Id in the Accounting-Request packets for that session.
        Example, a string with an 8-digit upper case hexadecimal number, the first two digits increment on each reboot (wrapping every 256 reboots) and the next 6 digits counting from 0 for the first person logging in after a reboot up to 2^24-1, about 16 million.
        """
        self.counter += 1
        return self.counter
        # return str(random.randrange(1, sys.maxsize)) # range is inclusive


    def createSessionID(ip:str=None, session:int=0, timestampe:int=0) :
        """
        Returns a Cisco Session ID which is a 96-bit hex string representing
            [NAS-IP-Address][Session-Count][Timestamp]
            [   32-bits    ][   32-bits   ][ 32-bits ]
            where:
            NAS-IP-Address is the 32-bit hex representation of the NAD IP
            Session-Count is the 32-bit hex session counter
            Timestamp is the 32-bit hex representation of the time converted from the unix timestamp
            Example: C612851B0000000157D0F3B7

        :param: ip (str) : the IP address of the NAD initiating the RADIUS request
        :param: session () : the session counter of the RADIUS client's request
        :return: id (str) : the session ID string
        """
        log.info("RADIUS.createSessionID(",ip,",",session,")")

        octets = map(int, ip.split('.'))
        nad_ip_hex = '{0[0]:02X}{0[1]:02X}{0[2]:02X}{0[3]:02X}'.format(octets)
        count = '{:08X}'.format(session)
        timestamp = '{:08X}'.format(int(time.time()))

        log.info("RADIUS.createSessionID(",ip,",",session,"): ", nad_ip_hex+count+timestamp)
        return nad_ip_hex+count+timestamp



    @classmethod
    def redact(self, s:str=None, c:str='*') -> str:
        """
        Return a replacement string for s made of character c the same length as s.
        s : str a string to be redacted.
        c : str a character to replace each letter in string s.
        """
        return len(str(s)) * c


    @classmethod
    def generate_mac(self, oui:str=None, sep:str='-') -> str:
        """
        Returns a random MAC prefixed with the specified OUI.

        oui (string): sep the group sep; default is '-'.
        sep (str): digits the number of digits in the group.
        """
        if oui != None and not isinstance(oui, str): raise ValueError(f"RADNAD.generate_mac(oui): oui is not a string ({type(oui)})")
        # 16777216 == 2^24 and 'X' == capitalized hex
        oui = '{:06X}'.format(random.randint(1, 16777216)) if oui is None else oui  
        mac = oui + '{:06X}'.format(random.randint(1, 16777216))

        # Format MAC address with the specified sep between groups of digits.
        # The default format is the IEEE 802 format: XX-XX-XX-XX-XX-XX
        digits = 2 # number of digits per group
        groups = [] # onebyte or twobyte groups
        for n in range(0, 12, digits): # range(start, stop[, step])
            groups.append(mac[n:n+digits])
        return sep.join(groups)


    @classmethod
    def randomized_mac(self, oui:str=None) -> str:
        """
        Returns a randomized MAC address prefixed with the specified OUI or a randomized OUI if none is given.

        oui (str): an optional organizationally unique identifier (OUI).
        """
        oui = '{:06X}'.format(random.randint(1, 16777216)) if oui is None else oui  # 16777216 == 2^24
        mac = oui+'{:06X}'.format(random.randint(1, 16777216))  # 'X' == capitalized hex
        # return to_format(mac)
        return mac


    @classmethod
    def generate_port(self, type:str=NAS_PORT_TYPES[15]) -> int:
        """
        A string representing a unique port number.
        """
        if type not in self.NAS_PORT_TYPES: raise ValueError(f"Invalid NAS_PORT_TYPE: {type}")
        max = 24 # default
        max = 48 if type == 'Ethernet' else max
        max = 1000 if type == 'Wireless-802.11' else max
        max = 10000 if type == 'Virtual' else max
        return random.randrange(1, max) # range is inclusive

    NAS_PORT_TYPES = [
        # NAS-Port-Type convenience list
        # Type of physical port of the NAS authenticating the user.
        # It can be used instead of or in addition to the NAS-Port (5) attribute.
        # It is only used in Access-Request packets.
        # NAS-Port (5) or NAS-Port-Type or both SHOULD be present in an Access-Request packet.
        'Async', # ( 0) 
        'Sync', # ( 1) 
        'ISDN-Sync', # ( 2) ISDN Sync
        'ISDN-Async-V.120', # ( 3) ISDN Async V.120
        'ISDN-Async-V.110', # ( 4) ISDN Async V.110
        'Virtual', # ( 5) Use this for VPN
        'PIAFS', # ( 6) 
        'HDLC-Clear-Channel', # ( 7) HDLC Clear Channel
        'X.25', # ( 8) 
        'X.75', # ( 9) 
        'G.3-Fax', # (10) G.3 Fax
        'SDSL', # (11) Symmetric DSL
        'ADSL-CAP', # (12) Asymmetric DSL, Carrierless Amplitude Phase Modulation
        'ADSL-DMT', # (13) Asymmetric DSL, Discrete Multi-Tone
        'IDSL', # (14) ISDN Digital Subscriber Line
        'Ethernet', # (15) Ethernet (wired)
        'xDSL', # (16)  - Digital Subscriber Line of unknown type
        'Cable', # (17) 
        'Wireless-Other', # (18) Wireless - Other
        'Wireless-802.11', # (19) Wireless - IEEE 802.11
    ]


    @classmethod
    def generate_ip_address(self) -> str:
        """
        Returns a random IP address string.
        """
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(2,254)}"


    @classmethod
    def to_avp_string(self, attributes:dict=None) -> str:
        """
        Return a single string containing comma-separated key=value pairs.
        The values are wrapped in double-quotes in case they contain ine may fail with :'s or ='s
            "Cisco-AVPair='profile-name=Unknown's"

        - attributes (dict or MultiDict): a dictionary of RADIUS attributes
        """
        return ", ".join([f"{key}='{val}'" for key,val in attributes.items()])


    async def _radclient_cli_cmd(self, attributes:dict=None) -> RADIUSResponse:
        """
        Performs a `radclient` CLI command and return a RADIUSResponse with the result.
        """
        attrs_string = self.to_avp_string(attributes)  # Stringify attrs for radclient CLI
        cmd = f"""echo "{attrs_string}" | radclient -x {self.server}:{self.auth_port} auth {self.secret}"""
        log.info(f"RADNAD.auth() cmd: {cmd}")

        # 🚧 ToDo: Prevent OSError: [Errno 24] Too many open files
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout,stderr = await process.communicate() # read a line of output from the program
        std_out = stdout.decode() # read stdout
        std_err = stderr.decode() # read stderr
        response = RADIUSResponse(std_out) # parses radclient output
        if std_err:
            log.error(f"{self.ICONS['ERROR']} {std_err}")
            print(f"{self.ICONS['ERROR']} {response.guess_access_method()} {response.req_attrs['Calling-Station-Id']} {response.req_attrs['User-Name']} {std_err}", end="", file=sys.stderr)
        return response


    async def auth(self, attributes:dict=None) -> str:
        """
        Performs a `radclient` authentication and returns a RADIUSResponse object.

        - attributes (dict or MultiDict): a dictionary of RADIUS attributes
        - raises TimeoutError

        Require use of MultiDict to support these protocol requirements:
        📄 RFC2866: Some attributes MAY be included more than once.
        📄 RFC2866: The order of Attributes with the same Type MUST be preserved by any proxies.
        📄 RFC2866: The client MUST NOT require attributes of the same type to be contiguous.
        """
        log.debug(f"▷ RADNAD.auth(attributes:{attributes})")

        if attributes is None: raise ValueError('attributes is None')
        if not isinstance(attributes, dict) and not isinstance(attributes, MultiDict): raise ValueError(f"attributes is not a dict or MultiDict: {type(attributes)}")
        if len(attributes) <= 0: raise ValueError('auth(attributes) is empty')

        if isinstance(attributes, dict):
            attributes = MultiDict(attributes) # upgrade dict to MultiDict

        if attributes.get('NAS-Identifier', None) is None: # add NAS-Identifier
            attributes['NAS-Identifier'] = self.name

        # ISE Error 11015: An Access-Request MUST contain at least a NAS-IP-Address, NAS-IPv6-Address, or a NAS-Identifier
        # 🚧 ToDo: Validate required RADIUS attributes
        if (attributes.get('NAS-IP-Address', None) is None and
            attributes.get('NAS-Identifier', None) is None and
            attributes.get('NAS-IPv6-Address', None) is None
           ):
            print(f"{self.ICONS['WARN']} Missing NAS-IP-Address, NAS-IPv6-Address, or a NAS-Identifier", file=sys.stderr)

        # 📄 RFC2866: User-Name MUST be sent in Access-Request packets if available
        if attributes.get('User-Name', None) is None:
            print(f"{self.ICONS['ERROR']} Missing User-Name", file=sys.stderr)

        if attributes.get('User-Password', None) is None: 
            print(f"{self.ICONS['ERROR']} Missing User-Password", file=sys.stderr)

        if attributes.get('Calling-Station-Id', None) is None:
            print(f"{self.ICONS['ERROR']} Missing Calling-Station-Id", file=sys.stderr)

        # 📄 RFC2866: An Access-Request packet MAY have an Acct-Session-Id
        # ✅ We definitely want one
        attributes['Acct-Session-Id'] = self.generate_session_id()

        # 📄 RFC2866: No other Attributes defined in this document are permitted in an Access-Challenge.

        return await self._radclient_cli_cmd(attributes)


    async def acct(self, auth:RADIUSResponse=None, state:str=ACCT_START):
        """
        Uses the `auth` RADIUSResponse to send a RADIUS accounting start message to the RADIUS server.

        - auth (RADIUSResponse): an authentication RADIUSResponse.
        - raises TimeoutError

        🚧 ToDo: Which attributes are required to Start a session in ISE?
        - User-Name
        - Calling-Station-Id
        - Service-Type
        - NAS-Port-Type
        - NAS-Identifier
        - Class
        - Framed-IP-Address
        - Acct-Status-Type
        - Acct-Session-Id
        """
        log.debug(f"▷ RADNAD.acct(auth: {auth}, state:{state})")

        if auth is None: raise ValueError(f"acct(auth) is None")
        if not isinstance(auth, RADIUSResponse): raise ValueError(f"acct(auth) is not type RADIUSResponse: {type(auth)}")
        if len(auth.req_attrs) <= 0: raise ValueError(f"auth.req_attrs is empty")
        if auth.rsp_type == auth.ACCESS_REJECT:
            log.error(f" ACCESS-REJECTED: Nothing to account {auth}")
            return auth
        if state != self.ACCT_START and state != self.ACCT_STOP: raise ValueError(f"acct(state) is invalid")

        if len(auth.rsp_attrs) <= 0: raise ValueError(f"auth.rsp_attrs is empty: {auth}")

        # Merge all auth request & response attributes into a single list
        attrs = MultiDict(auth.req_attrs)
        attrs.update(auth.rsp_attrs)

        # 📄 RFC2866: The following attributes MUST NOT be present in an Accounting-Request:
        #    - User-Password
        #    - CHAP-Password
        #    - Reply-Message
        #    - State
        attrs.pop('User-Password', '')
        attrs.pop('CHAP-Password', '')
        attrs.pop('Reply-Message', '')
        attrs.pop('State', '')
        attrs.pop('Cleartext-Password', '') # added by radclient for PAP & CHAP authentications

        # 🚧 ToDo: Differentiate Session Start vs Stop?
        attrs['Acct-Status-Type'] = state    # ACCT_START | ACCT_STOP

        # 📄 RFC2866: An Accounting-Request packet MUST have an Acct-Session-Id.
        # 📄 RFC2866: An Access-Request MAY have an Acct-Session-Id; if so, it MUST in the Accounting-Request packets for that session.
        # ✅ Verify there is an Acct-Session-Id
        if attrs.get('Acct-Session-Id', None) is None:
            attrs['Acct-Session-Id'] = self.generate_session_id()

        # 📄 RFC2866: NAS-IP-Address or NAS-Identifier MUST be present:
        attrs['NAS-Identifier'] = self.name # add NAS info
        # 🚧 ToDo: Don't know the best / fastest / easiest method to get our local IP address
        # attrs['NAS-IP-Address'] = ???

        # 📄 RFC2866: Framed-IP-Address MUST contain the IP address of the user whether assigned or negotiated.
        attrs['Framed-IP-Address'] = self.generate_ip_address()
        
        # 📄 RFC2866: SHOULD contain a NAS-Port or NAS-Port-Type attribute or both unless the service does not distinguish its ports.
        if attrs.get('NAS-Port', None) is None and attrs.get('NAS-Port-Type', None) is None:
            print(f"{self.ICONS['WARN']} No NAS-Port or NAS-Port-Type", file=sys.stderr)

        attrs_string = self.to_avp_string(attrs)  # Stringify attrs for radclient CLI
        cmd = f"""echo "{attrs_string}" | radclient -x {self.server}:{self.acct_port} acct {self.secret}"""
        log.info(f"RADNAD.acct() cmd: {cmd}")

        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout,stderr = await process.communicate() # read a line of output from the program
        std_out = stdout.decode() # read stdout
        std_err = stderr.decode() # read stderr
        if std_err: log.error(f"{self.ICONS['ERROR']} {std_err}")

        return RADIUSResponse(std_out) # parses radclient output


    async def acct_stop(self, response:RADIUSResponse=None, state:str=ACCT_STOP):
        """
        Send RADIUS Accounting Stop.

        The only things ISE requires for an Accounting Stop are
        - User-Name           # Does not like MAC for MAB
        - Calling-Station-Id
        - Acct-Status-Type    # Must be 'Stop'
        - Acct-Session-Id     # May be anything but must include something
        """
        log.debug(f"▷ RADNAD.acct_stop(response={response}, state={state})")

        # 🚧 ToDo: 📄 RFC2866: The start and stop records for a given session MUST have the same Acct-Session-Id.
        # 🚧 ToDo: 📄 RFC2866

        # This attribute indicates how many seconds the user has received service for, and can only be present in Accounting-Request records where the Acct-Status-Type is set to Stop.
        attrs['Acct-Session-Time'] = (datetime.datetime.now(tz=None) - response.timestamp).seconds

        # 🚧 ToDo - use return await self._radclient_cli_cmd(attributes)
        attrs_string = self.to_avp_string(attrs)  # Stringify attrs for radclient CLI
        cmd = f"""echo "{attrs_string}" | radclient -x {self.server}:{self.acct_port} acct {self.secret}"""
        log.info(f"RADNAD.acct() cmd: {cmd}")

        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout,stderr = await process.communicate() # read a line of output from the program
        std_out = stdout.decode() # read stdout
        std_err = stderr.decode() # read stderr
        if std_err: log.error(f"{self.ICONS['ERROR']} {std_err}")
        return RADIUSResponse(std_out) # parses radclient output


    async def acct_stop_by_attrs(self, attrs:dict=None):
        """
        Send RADIUS Accounting Stop.

        The minimum attributes required by ISE for an Accounting Stop are:
        - User-Name           # Does not like MAC for MAB
        - Calling-Station-Id
        - Acct-Status-Type    # Must be 'Stop'
        - Acct-Session-Id     # May be anything but must include something
        """
        if attrs is None: raise ValueError(f"attrs is None")
        log.debug(f"▷ RADNAD.acct_stop(attrs={attrs})")

        # 📄 RFC2866: The start and stop records for a given session MUST have the same Acct-Session-Id.
        if attrs.get('Acct-Session-Id', None) is None: raise ValueError(f"Acct-Session-Id is None")
        if attrs.get('User-Name', None) is None: raise ValueError(f"User-Name is None")
        if attrs.get('Calling-Station-Id', None) is None:  raise ValueError(f"Calling-Station-Id is None")

        # Add Acct-Status-Type if it does not exist
        if attrs.get('Acct-Status-Type', None) is None:
            attrs['Acct-Status-Type'] = self.ACCT_STOP

        # 📄 RFC2866: Acct-Session-Time can only be present in Accounting-Request records where the Acct-Status-Type is set to Stop
        #    Acct-Session-Time indicates how many seconds the user has received service for.
        if attrs.get('Timestamp', None) != None:
            attrs['Acct-Session-Time'] = (datetime.datetime.now(tz=None) - attrs.get('Timestamp')).seconds

        # 🚧 ToDo - use return await self._radclient_cli_cmd(attributes)
        attrs_string = self.to_avp_string(attrs)  # Stringify attrs for radclient CLI
        cmd = f"""echo "{attrs_string}" | radclient -x {self.server}:{self.acct_port} acct {self.secret}"""
        log.info(f"RADNAD.acct() cmd: {cmd}")

        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout,stderr = await process.communicate() # read a line of output from the program
        std_out = stdout.decode() # read stdout
        std_err = stderr.decode() # read stderr
        if std_err: log.error(f"{self.ICONS['ERROR']} {std_err}")

        response = RADIUSResponse(std_out) # parses radclient output
        # print(f"{self.ICONS['INFO']} Acct STOP response: {response.is_accepted()}\n{response}", file=sys.stderr)
        if response.is_accepted(): # Remove session
            self.sessions.drop(self.sessions.loc[self.sessions['Acct-Session-Id'] == attrs.get('Acct-Session-Id')].index, inplace=True)
            # print(f"{self.ICONS['STOP']} Removed session-id: {attrs.get('Acct-Session-Id')} {attrs.get('User-Name')}", file=sys.stderr)
        return response


    async def auto(self, ):
        """
        🚧 ToDo - Not Implemented.
        """
        log.error(f"▷ RADNAD.auto() 🚧 NOT IMPLEMENTED")


    async def status(self, ):
        """
        🚧 ToDo - Not Implemented.
        From https://wiki.freeradius.org/config/Status
        Example command:
            echo "Message-Authenticator = 0x00, FreeRADIUS-Statistics-Type = 1, Response-Packet-Type = Access-Accept" | radclient -x radius-server status secret
        """
        log.error(f"▷ RADNAD.status() 🚧 NOT IMPLEMENTED")


    async def coa(self, ):
        """
        🚧 ToDo - Not Implemented.
        Example command:
            echo "User-Name:=testuser124,Mikrotik-Rate-Limit:=\"10000k/12000k\"" | /usr/bin/radclient -r 1 10.0.0.60:1700 coa secret

        📄 RFC3576
        To centrally control the disconnection of remote access users, 
        RADIUS clients must be able to receive and process unsolicited 
        disconnect requests from RADIUS servers. The RADIUS disconnect 
        feature uses the existing format of RADIUS disconnect request 
        and response messages.

        The Code field is one octet, and identifies the type of RADIUS packet.
        Packets received with an invalid Code field MUST be silently discarded.
        RADIUS codes (decimal) for this extension are assigned as follows:

            40 - Disconnect-Request [RFC2882]
            41 - Disconnect-ACK [RFC2882]
            42 - Disconnect-NAK [RFC2882]
            43 - CoA-Request [RFC2882]
            44 - CoA-ACK [RFC2882]
            45 - CoA-NAK [RFC2882]

        In Disconnect-Request and CoA-Request packets, certain attributes are
        used to uniquely identify the NAS as well as a user session on the
        NAS.  All NAS identification attributes included in a Request message
        MUST match in order for a Disconnect-Request or CoA-Request to be
        successful; otherwise a Disconnect-NAK or CoA-NAK SHOULD be sent.
        For session identification attributes, the User-Name and Acct-
        Session-Id Attributes, if included, MUST match in order for a
        Disconnect-Request or CoA-Request to be successful; other session
        identification attributes SHOULD match.  Where a mismatch of session
        identification attributes is detected, a Disconnect-NAK or CoA-NAK
        SHOULD  be sent.  The ability to use NAS or session identification
        attributes to map to unique/multiple sessions is beyond the scope of
        this document.  Identification attributes include NAS and session
        identification attributes, as described below.

        NAS identification attributes

        Attribute              #    Reference  Description
        ---------             ---   ---------  -----------
        NAS-IP-Address         4    [RFC2865]  The IPv4 address of the NAS.
        NAS-Identifier        32    [RFC2865]  String identifying the NAS.
        NAS-IPv6-Address      95    [RFC3162]  The IPv6 address of the NAS.

        Session identification attributes

        Attribute              #    Reference  Description
        ---------             ---   ---------  -----------
        User-Name              1    [RFC2865]  The name of the user associated with the session.
        NAS-Port               5    [RFC2865]  The port on which the session is terminated.
        Framed-IP-Address      8    [RFC2865]  The IPv4 address associated with the session.
        Called-Station-Id     30    [RFC2865]  The link address to which the session is connected.
        Calling-Station-Id    31    [RFC2865]  The link address from which the session is connected.
        Acct-Session-Id       44    [RFC2866]  The identifier uniquely identifying the session on the NAS.
        Acct-Multi-Session-Id 50    [RFC2866]  The identifier uniquely identifying related sessions.
        NAS-Port-Type         61    [RFC2865]  The type of port used.
        NAS-Port-Id           87    [RFC2869]  String identifying the port where the session is.
        Originating-Line-Info 94    [NASREQ]   Provides information on the characteristics of the line from which a session originated.
        Framed-Interface-Id   96    [RFC3162]  The IPv6 Interface Identifier associated with the session; always sent with Framed-IPv6-Prefix.
        Framed-IPv6-Prefix    97    [RFC3162]  The IPv6 prefix associated with the session, always sent with Framed-Interface-Id.

        To address security concerns described in Section 5.1., the User-Name
        Attribute SHOULD be present in Disconnect-Request or CoA-Request
        packets; one or more additional session identification attributes MAY
        also be present.  To address security concerns described in Section
        5.2., one or more of the NAS-IP-Address or NAS-IPv6-Address
        Attributes SHOULD be present in Disconnect-Request or CoA-Request
        packets; the NAS-Identifier Attribute MAY be present in addition.

        If one or more authorization changes specified in a CoA-Request
        cannot be carried out, or if one or more attributes or attribute-
        values is unsupported, a CoA-NAK MUST be sent.  Similarly, if there
        are one or more unsupported attributes or attribute values in a
        Disconnect-Request, a Disconnect-NAK MUST be sent.

        """
        log.error(f"▷ RADNAD.coa() 🚧 NOT IMPLEMENTED")


    async def disconnect(self, ):
        """
        🚧 ToDo - Not Implemented.
        Disconnect Requests.
        See the 📄 RFC3576 descriptions in coa() above.
        See https://wiki.freeradius.org/protocol/Disconnect-Messages
        """
        log.error(f"▷ RADNAD.disconnect() 🚧 NOT IMPLEMENTED")


    #
    # RADIUS Session Convenience Methods
    #


    # async def session(self, attrs:dict=None, response_handler:callable=session_response_handler):
    async def session(self, attrs:dict=None):
        """
        Convenience function to perform both authentication and authorization to create a session.
        A session is started upon the acknowledgment of the accounting request from the RADIUS server.

        - attrs (dict or MultiDict): a dictionary of RADIUS attributes to use for the authentication.
        - response_handler (callable): a function to handle the session response.
        - raises TimeoutError
        """
        # log.debug(f"▷ RADNAD.session(attrs:{attrs}, response_handler:{response_handler})")
        log.debug(f"▷ RADNAD.session(attrs:{attrs})")

        # Perform an authentication with the specified attributes
        response = await self.auth(attrs)    # returns RADIUSResponse
        if response.rsp_type == RADIUSResponse.ACCESS_ACCEPT:
            # Authentication Passed
            log.info(f"{self.RESPONSE_ICONS[response.rsp_type]} {response.rsp_type} {response.__dict__}")

            # Send Accounting request
            response = await self.acct(response) # returns RADIUSResponse
            if response.rsp_type == RADIUSResponse.ACCOUNTING_RESPONSE:
                log.info(f"{self.RESPONSE_ICONS[response.rsp_type]} {response.rsp_type} {response.__dict__}")
                await self.create_session(response)

        elif response.rsp_type == RADIUSResponse.ACCESS_REJECT:
            # Authentication Failed
            log.error(f"{self.RESPONSE_ICONS[response.rsp_type]} {response.rsp_type} {response.__dict__}")

        elif response.rsp_type == RADIUSResponse.ACCESS_CHALLENGE:
            print(f"{self.RESPONSE_ICONS[response.rsp_type]} Response type: {response.rsp_type} is NOT SUPPORTED", file=sys.stderr)
            log.error(f"{self.RESPONSE_ICONS[response.rsp_type]} Response type: {response.rsp_type} is NOT SUPPORTED")

        else:
            print(f"{self.RESPONSE_ICONS[response.rsp_type]} auth_acct(): Unknown response type: {response.rsp_type}", file=sys.stderr)
            log.error(f"{self.RESPONSE_ICONS[response.rsp_type]} auth_acct(): Unknown response type: {response.rsp_type}")

        return response


    async def dot1x_wired_pap(self, username:str=None, password:str=None, calling:str=None, called:str=None, nas_port_id=None, attributes:dict=None):
        """
        Convenience function to perform a RADIUS wired PAP authentication and accounting request.
        `radclient` can only perform authentications using the PAP method.

        :param username (str) : the user's identity (`User-Name`)
        :param password (str) : the user's password (`User-Password`)
        :param calling (str) : the MAC address of the endpoint being authenticated (`Calling-Station-Id`).
        :param called (str) : the MAC address of the network device port (`Called-Station-Id`).
        :param attributes (dict) : a dictionary of RADIUS attributes for the authentication attempt.
        :return (RADIUSResponse) : the RADIUSRespone object from the request.
        :raise TimeoutError
        """
        log.debug(f"▷ RADNAD.dot1x_wired_pap(username:{username}, password:{len(password)*'*'}, calling:{calling}, called:{called}, attributes:{attributes})")

        attrs = MultiDict({
            'Service-Type': 'Framed',
            'NAS-Port-Type': 'Ethernet',
            'NAS-Port-Id': calling if nas_port_id is None else nas_port_id,
            'NAS-Port': self.generate_port(self.NAS_PORT_TYPES[15]),
        })

        if username is None or username == '': raise ValueError('username is empty')
        attrs['User-Name'] = username

        if password is None or password == '': raise ValueError('password is empty')
        attrs['User-Password'] = password

        # Optional Attributes
        if calling != None and calling != '': attrs['Calling-Station-Id'] = calling # 💡 Required for ISE RADIUS session
        if called: attrs['Called-Station-Id'] = called
        if attributes and len(attributes) > 0:
            attrs.update(attributes) # override defaults

        return await self.session(attrs)


    async def mab_wired(self, calling:str=None, called:str=None, nas_port_id=None, attributes:dict=None):
        """
        Convenience function for a RADIUS wired MAB authentication + accounting request.
        Returns RADIUSResponse the RADIUSRespone object from the request.

        :param calling (str) : the MAC address of the endpoint being authenticated (`Calling-Station-Id`).
        :param called (str) : the MAC address of the network device port (`Called-Station-Id`).
        :param attributes (dict) : a dictionary of RADIUS attributes for the authentication attempt.
        :return (RADIUSResponse) : the RADIUSRespone object from the request.
        :raise TimeoutError

        Example packet capture of Authentication Attribute Value Pairs (AVPs)
            AVP: t=User-Name(1) l=14 val=dca6326da3ba
            AVP: t=User-Password(2) l=18 val=Encrypted
            AVP: t=Service-Type(6) l=6 val=Call-Check(10)
            AVP: t=Vendor-Specific(26) l=31 vnd=ciscoSystems(9)
            AVP: t=Framed-MTU(12) l=6 val=1468
            AVP: t=Message-Authenticator(80) l=18 val=c77f69ce976ed6d0849d702f770fe79a
            AVP: t=EAP-Key-Name(102) l=2 val=
            AVP: t=Vendor-Specific(26) l=49 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=43 val=audit-session-id=010301010000000CE40851D3
                    Cisco-AVPair: audit-session-id=010301010000000CE40851D3
            AVP: t=Vendor-Specific(26) l=18 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=12 val=scenario=mab
                    Cisco-AVPair: scenario=mab
            AVP: t=Vendor-Specific(26) l=31 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=25 val=client-iif-id=514364284
                    Cisco-AVPair: client-iif-id=514364284
            AVP: t=NAS-IP-Address(4) l=6 val=10.80.60.152
            AVP: t=NAS-Port-Id(87) l=21 val=2C:3F:0B:16:75:80/1
            AVP: t=NAS-Port-Type(61) l=6 val=Ethernet(15)
            AVP: t=NAS-Port(5) l=6 val=50101
            AVP: t=Calling-Station-Id(31) l=19 val=DC-A6-32-6D-A3-BA
            AVP: t=Called-Station-Id(30) l=19 val=2C-3F-0B-16-75-81

        Example packet capture of Authentication Access-Accept Attribute Value Pairs (AVPs)
            AVP: t=User-Name(1) l=19 val=DC-A6-32-6D-A3-BA
            AVP: t=Class(25) l=48 val=434143533a3031303330313031303030303030304345343038353144333a6…
            AVP: t=Message-Authenticator(80) l=18 val=345024861a5e140bcb14cc96858d94c0
            AVP: t=Vendor-Specific(26) l=39 vnd=ciscoSystems(9)
                Type: 26
                Length: 39
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=33 val=profile-name=RaspberryPi-Device
                    Type: 1
                    Length: 33
                    Cisco-AVPair: profile-name=RaspberryPi-Device
        """
        log.debug(f"▷ RADNAD.mab_wired(calling:{calling}, called:{called}, attributes:{attributes})")

        # Required attributes
        attrs = MultiDict({
            'Service-Type': 'Call-Check',
            'NAS-Port-Type': 'Ethernet',
            'NAS-Port-Id': calling if nas_port_id is None else nas_port_id,
            'NAS-Port': self.generate_port(self.NAS_PORT_TYPES[15]),
        })

        # Validations
        if calling is None or calling == '': raise ValueError('calling is empty')
        attrs['User-Name'] = calling
        attrs['User-Password'] = calling
        attrs['Calling-Station-Id'] = calling

        # Optional Attributes
        if called:
            attrs['Called-Station-Id'] = called
        if attributes and len(attributes) > 0:
            attrs.update(attributes)

        return await self.session(attrs)


    async def dot1x_wireless_pap(self, username:str=None, password:str=None, calling:str=None, called:str=None, nas_port_id=None, attributes:dict=None):
        """
        Convenience function for a RADIUS wired PAP authentication + accounting request.
        `radclient` can only perform authentications using the PAP method.

        :param username (str) : the user's identity (`User-Name`)
        :param password (str) : the user's password (`User-Password`)
        :param calling (str) : the MAC address of the endpoint being authenticated (`Calling-Station-Id`).
        :param called (str) : the MAC address of the network device port (`Called-Station-Id`).
        :param attributes (dict) : a dictionary of RADIUS attributes for the authentication attempt.
        :return (RADIUSResponse) : the RADIUSRespone object from the request.
        :raise TimeoutError
        """
        log.debug(f"▷ RADNAD.dot1x_wireless_pap(username:{username}, password:{len(password)*'*'}, calling:{calling}, called:{called}, attributes:{attributes})")

        attrs = MultiDict({
            'Service-Type': 'Framed',
            'NAS-Port-Type': 'Wireless-802.11',
            'NAS-Port-Id': calling if nas_port_id is None else nas_port_id,
            'NAS-Port': self.generate_port(self.NAS_PORT_TYPES[19]),
        })

        if username is None or username == '': raise ValueError('username is empty')
        attrs['User-Name'] = username

        if password is None or password == '': raise ValueError('password is empty')
        attrs['User-Password'] = password

        # Optional Attributes
        if calling != None and calling != '': attrs['Calling-Station-Id'] = calling # 💡 Required for ISE RADIUS session
        if called: attrs['Called-Station-Id'] = called
        if attributes and len(attributes) > 0:
            attrs.update(attributes) # override defaults

        return await self.session(attrs)


    async def mab_wireless(self, calling:str=None, called:str=None, attributes:dict=None, nas_port_id=None, ssid:str=None):
        """
        Convenience function for a RADIUS wired MAB authentication + accounting request.
        Returns RADIUSResponse the RADIUSRespone object from the request.

        :param calling (str) : the MAC address of the endpoint being authenticated (`Calling-Station-Id`).
        :param called (str) : the MAC address of the network device port (`Called-Station-Id`).
        :param attributes (dict) : a dictionary of RADIUS attributes for the authentication attempt.
        :return (RADIUSResponse) : the RADIUSRespone object from the request.
        :raise TimeoutError

        Example packet capture of Authentication Request Attribute Value Pairs (AVPs)
            AVP: t=Service-Type(6) l=6 val=Call-Check(10)
            AVP: t=User-Name(1) l=14 val=dca6326da3bb
            AVP: t=User-Password(2) l=18 val=Encrypted
            AVP: t=NAS-IP-Address(4) l=6 val=10.80.60.152
            AVP: t=NAS-Identifier(32) l=24 val=2C-3F-0B-56-E3-6C:vap1
            AVP: t=NAS-Port-Type(61) l=6 val=Wireless-802.11(19)
            AVP: t=Vendor-Specific(26) l=22 vnd=Meraki Networks, Inc.(29671)
                Vendor ID: Meraki Networks, Inc. (29671)
                VSA: t=Meraki-Network-Name(2) l=16 val=Lab - wireless
            AVP: t=Vendor-Specific(26) l=18 vnd=Meraki Networks, Inc.(29671)
                Vendor ID: Meraki Networks, Inc. (29671)
                VSA: t=Meraki-Ap-Name(3) l=12 val=lab-mr46-1
            AVP: t=Vendor-Specific(26) l=8 vnd=Meraki Networks, Inc.(29671)
                Vendor ID: Meraki Networks, Inc. (29671)
                VSA: t=Meraki-Ap-Tags(4) l=2 val=
            AVP: t=Called-Station-Id(30) l=24 val=2C-3F-0B-56-E3-6C:.iot
            AVP: t=Vendor-Specific(26) l=18 vnd=Meraki Networks, Inc.(29671)
            AVP: t=Calling-Station-Id(31) l=19 val=DC-A6-32-6D-A3-BB
            AVP: t=Connect-Info(77) l=24 val=CONNECT 11Mbps 802.11b
            AVP: t=Message-Authenticator(80) l=18 val=030a71cd41646baa446c39af66c13a35

        Example packet capture of Authentication Access-Accept Attribute Value Pairs (AVPs)
            AVP: t=User-Name(1) l=19 val=DC-A6-32-6D-A3-BB
            AVP: t=Class(25) l=75 val=434143533a633631323835316271316f796c767342743335…
            AVP: t=Tunnel-Password(69) l=21 Tag=0x01 val=Encrypted
            AVP: t=Message-Authenticator(80) l=18 val=948405e4e734bf63645615396cf77999
            AVP: t=Vendor-Specific(26) l=22 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=16 val=psk-mode=ascii
            AVP: t=Vendor-Specific(26) l=16 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=10 val=Ktghmo9M
            AVP: t=Vendor-Specific(26) l=38 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=32 val=cts:security-group-tag=0010-00
        """
        log.debug(f"▷ RADNAD.mab_wireless(calling:{calling}, called:{called}, attributes:{attributes}), ssid:{ssid}")

        # Required attributes
        attrs = MultiDict({
            'Service-Type': 'Call-Check',
            'NAS-Port-Type': 'Wireless-802.11',
            'NAS-Port-Id': calling if nas_port_id is None else nas_port_id,
            'NAS-Port': self.generate_port(self.NAS_PORT_TYPES[19]),
        })

        # Validations
        if calling is None or calling == '': raise ValueError('calling is empty')
        attrs['User-Name'] = calling
        attrs['User-Password'] = calling
        attrs['Calling-Station-Id'] = calling

        # Optional Attributes
        if called: 
            attrs['Called-Station-Id'] = f"{called}:{ssid}" if ssid else called  # called:ssid
        if attributes and len(attributes) > 0:
            attrs.update(attributes) # override defaults

        return await self.session(attrs)


    async def vpn(self, username:str=None, password:str=None, calling:str=None, called:str=None, nas_port_id=None, attributes:dict=None):
        """
        Convenience function for a RADIUS wired PAP authentication + accounting request.
        `radclient` can only perform authentications using the PAP method.
        Returns RADIUSResponse the RADIUSRespone object from the request.

        :param username (str) : the user's identity (`User-Name`)
        :param password (str) : the user's password (`User-Password`)
        :param calling (str) : the MAC address of the endpoint being authenticated (`Calling-Station-Id`).
        :param called (str) : the MAC address of the network device port (`Called-Station-Id`).
        :param attributes (dict) : a dictionary of RADIUS attributes for the authentication attempt.
        :return (RADIUSResponse) : the RADIUSRespone object from the request.
        :raise TimeoutError
        """

        """
        Returns a dictionary of RADIUS attributes for a MAC Authentication Bypass (MAB) wired authentication request from the specified arguments.
        `radclient` can only perform authentications using the PAP method.

        :param calling (str) : the MAC address of the endpoint being authenticated (`Calling-Station-Id`).
        :param called (str) : the MAC address of the network device port (`Called-Station-Id`).
        :param attributes (dict) : a dictionary of RADIUS attributes for the authentication attempt.
        :return (MultiDict) : a dictionary of RADIUS attributes describing the authentication request.

        Example packet capture of Authentication Request Attribute Value Pairs (AVPs)
            AVP: t=User-Name(1) l=10 val=employee
            AVP: t=NAS-Port(5) l=6 val=16384
            AVP: t=Called-Station-Id(30) l=15 val=198.19.10.100
            AVP: t=Calling-Station-Id(31) l=14 val=198.19.10.37
            AVP: t=NAS-Port-Type(61) l=6 val=Virtual(5)
            AVP: t=Tunnel-Client-Endpoint(66) l=14 val=198.19.10.37
            AVP: t=Vendor-Specific(26) l=24 vnd=Microsoft(311)
                Vendor ID: Microsoft (311)
                VSA: t=MS-CHAP-Challenge(11) l=18 val=5deb2cc76b054e7ffb4f11a9243d4eb6
            AVP: t=Vendor-Specific(26) l=58 vnd=Microsoft(311)
                Vendor ID: Microsoft (311)
                VSA: t=MS-CHAP2-Response(25) l=52 val=0000bbb64abc546c3f581b81e057b78a575b0000000000000000eef35c29c48925ba9cd5…
            AVP: t=Vendor-Specific(26) l=35 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=29 val=mdm-tlv=device-platform=win
            AVP: t=Vendor-Specific(26) l=44 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=38 val=mdm-tlv=device-mac=00-50-5a-aa-8a-4a
            AVP: t=Vendor-Specific(26) l=51 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=45 val=mdm-tlv=device-platform-version=10.0.19044 
            AVP: t=Vendor-Specific(26) l=51 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=45 val=mdm-tlv=device-public-mac=00-50-5a-aa-8a-4a
            AVP: t=Vendor-Specific(26) l=59 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=53 val=mdm-tlv=ac-user-agent=AnyConnect Windows 4.10.04065
            AVP: t=Vendor-Specific(26) l=64 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=58 val=mdm-tlv=device-type=VMware, Inc. VMware Virtual Platform
            AVP: t=Vendor-Specific(26) l=74 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=68 val=mdm-tlv=device-uid-global=68616875A273996ED3A21E26B8371A168FAAF526
            AVP: t=Vendor-Specific(26) l=91 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=85 val=mdm-tlv=device-uid=F14ADF3139770E9AAD19D617F97976019D9EC6B72FF7580C749D36CFA8F73098
            AVP: t=NAS-IP-Address(4) l=6 val=198.18.133.100
            AVP: t=Vendor-Specific(26) l=49 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=43 val=audit-session-id=c612856400004000642c96a9
            AVP: t=Vendor-Specific(26) l=33 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=27 val=ip:source-ip=198.19.10.37
            AVP: t=Vendor-Specific(26) l=26 vnd=Altiga Networks, Inc.(3076)
                Vendor ID: Altiga Networks, Inc. (3076)
                VSA: t=ASA-TunnelGroupName(146) l=20 val=DefaultWEBVPNGroup
            AVP: t=Vendor-Specific(26) l=12 vnd=Altiga Networks, Inc.(3076)
                Vendor ID: Altiga Networks, Inc. (3076)
                VSA: t=ASA-ClientType(150) l=6 val=AnyConnect-Client-SSL-VPN(2)
            AVP: t=Vendor-Specific(26) l=21 vnd=ciscoSystems(9)
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=15 val=coa-push=true

        Example packet capture of Authentication Access-Accept Attribute Value Pairs (AVPs)
            AVP: t=User-Name(1) l=10 val=employee
            AVP: t=Class(25) l=48 val=434143533a6336313238353634303030303430303036343263393661393a6973652f3436…
            AVP: t=Vendor-Specific(26) l=38 vnd=ciscoSystems(9)
                Type: 26
                Length: 38
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=32 val=cts:security-group-tag=0011-25
            AVP: t=Vendor-Specific(26) l=42 vnd=ciscoSystems(9)
                Type: 26
                Length: 42
                Vendor ID: ciscoSystems (9)
                VSA: t=Cisco-AVPair(1) l=36 val=profile-name=Windows10-Workstation
            AVP: t=Vendor-Specific(26) l=51 vnd=Microsoft(311)
                Type: 26
                Length: 51
                Vendor ID: Microsoft (311)
                VSA: t=MS-CHAP2-Success(26) l=45 val=00533d3830304243314138323137423244363030343832433441344439…
        """
        log.debug(f"▷ RADNAD.vpn(username:{username}, password:{password}, calling:{calling}, called:{called}, attributes:{attributes})")

        # Required attributes
        attrs = MultiDict({
            # No 'Service-Type' for VPN
            'NAS-Port-Type': 'Virtual',
            'NAS-Port-Id': calling if nas_port_id is None else nas_port_id,
            'NAS-Port': self.generate_port(self.NAS_PORT_TYPES[5]),
        })

        # Validations
        if username is None or username == '': raise ValueError('username is empty')
        attrs['User-Name'] = username

        if password is None or password == '': raise ValueError('password is empty')
        attrs['User-Password'] = password

        if calling is None or calling == '': raise ValueError('calling is empty')

        # 🚧 ToDo: Validate Calling-Station-Id is an IP address for the VPN scenario!
        attrs['Calling-Station-Id'] = calling
        attrs['Tunnel-Client-Endpoint'] = calling # RADIUS Tunnel-Client-Endpoint (66)

        # 🚧 ToDo: Validate Called-Station-Id is an IP address for the VPN scenario!
        if called: attrs['Called-Station-Id'] = called
        if attributes and len(attributes) > 0:
            attrs.update(attributes) # override defaults

        return await self.session(attrs)


    async def web_auth () :
        """
        🚧 ToDo - Not Implemented.
        Convenience function for a RADIUS wired PAP authentication + accounting request.
        `radclient` can only perform authentications using the PAP method.

        :return (RADIUSResponse) : the RADIUSRespone object from the request.
        """
        log.warning(f"wireless_web_auth() 🚧 NOT IMPLEMENTED")


    #
    # Session Management
    #


    def get_sessions_by_id(self, id:int=0):
        """
        Return the session with the specified id or None if there is no such session id.
        :param id (int) : a session identifier
        """
        if id is None: return None
        # self.show_sessions()
        print(f"get_sessions_by_id(id={id}):\n{self.sessions['Acct-Session-Id']}")
        session_to_stop = self.sessions[self.sessions['Acct-Session-Id'] == id]
        print(f"get_sessions_by_id(id={id}) [{len(session_to_stop)}]:\n{session_to_stop}")
        return session_to_stop


    def get_sessions(self): # , conditions=None):
        """
        Return all sessions or only those matching the filter, if provided.
        # :param filter () : a filter
        """
        # if filter is not None:
        #     print(f"filter: {conditions}")
        #     return self.sessions.loc[conditions]
        # else:
        return self.sessions.copy()


    def get_session_count(self):
        """
        Return total number of active sessions, loading from persistence, if necessary.
        """
        # return len(self.sessions[self.sessions['Status'] == self.ACCT_START])
        return len(self.sessions)


    def get_sessions_by_status(self, status:str=None):
        """
        Return the DataFrame of sessions, loading from persistence, if necessary.
        :param status (str) : filter sessions by the status
        """
        if not status in [self.ACCT_START,self.ACCT_STOP]: raise ValueError(f"Invalid status: {status}")
        log.debug(f"▷ RADNAD.get_sessions_by_status(status={status})")
        return self.sessions[self.sessions['Status'] == status]


    async def create_session(self, response:RADIUSResponse=None):
        """
        Create a new session entry from the `RADIUSResponse` which must be an Accounting-Response`.
        :param response (RADIUSResponse) : a RADIUS Accounting response in the form of a `RADIUSResponse`.
        """
        if response is None: log.error(f"create_session(): response is None")
        if response.rsp_type != RADIUSResponse.ACCOUNTING_RESPONSE: raise ValueError(f"RADIUS Response Type {response.rsp_type} is not {RADIUSResponse.ACCOUNTING_RESPONSE}")

        # 🚧 ToDo: Check for an existing session and update it!
        # Create a dictionary to map RADIUSResponse to SESSION_COLUMNS in DataFrame
        row = {
            'Timestamp'          : datetime.datetime.fromtimestamp(response.timestamp, tz=None).isoformat(sep=" ", timespec="milliseconds"),
            'Method'             : response.guess_access_method(),
            'Status'             : response.req_attrs.pop('Acct-Status-Type', self.ACCT_START),
            'User-Name'          : response.req_attrs.pop('User-Name', ''),
            'Calling-Station-Id' : response.req_attrs.pop('Calling-Station-Id', ''),
            'Framed-IP-Address'  : response.req_attrs.pop('Framed-IP-Address', ''),
            'Session-Timeout'    : response.req_attrs.pop('Session-Timeout', self.SESSION_TIMEOUT),
            'Acct-Session-Id'    : response.req_attrs.pop('Acct-Session-Id', ''),
            'Called-Station-Id'  : response.req_attrs.pop('Called-Station-Id', ''),
            'NAS-Port-Type'      : response.req_attrs.pop('NAS-Port-Type', ''),
            'NAS-Port-Id'        : response.req_attrs.pop('NAS-Port-Id', ''),
            'NAS-Port'           : response.req_attrs.pop('NAS-Port', ''),
            'NAS-Identifier'     : response.req_attrs.pop('NAS-Identifier', ''),
            'Class'              : response.req_attrs.pop('Class', ''),
            'Other'              : RADNAD.to_avp_string(response.req_attrs), # Append any remaining attribute-value-pairs into 'Other' for reference
        }
        new = pd.DataFrame([row]).set_index(['Timestamp'])
        self.sessions = pd.concat([self.sessions, new], axis='index')
        self.sessions.index = pd.to_datetime(self.sessions.index) # 💡 fix index after concat


    def show_sessions(self, sessions:pd.DataFrame=None):
        """
        Show the specified sessions in a table or all of the RADNAD's sessions.
        :param sessions (pandas.DataFrame) : filter sessions by the status: ['started','stopped','expired']
        """
        sessions = self.sessions.copy() if sessions is None else sessions
        log.info(f"show_sessions(): {len(sessions)}")
        if len(sessions) <= 0: return

        # Calculate Session Duration
        if len(sessions) > 0:
            sessions['Duration'] = (datetime.datetime.now(tz=None) - sessions.index).seconds
            print(f"All Sessions by Duration\n{sessions.sort_values(by=['Duration']).drop(columns=RADNAD.HIDE_COLUMNS).infer_objects(copy=False).reset_index().to_string(index=False)}")
            log.info(f"▷ RADNAD.show_sessions(): {len(self.sessions)} sessions")


    async def stop_expired_sessions(self) -> [RADIUSResponse]:
        """
        Stop all expired sessions and return the stopped sessions' `RADIUSResponse`s.
        return: ([RADIUSResponse]) : a list of RADIUSResponse or an empty list if there are none.
        """

        # Drop any sessions with a Duration > 4 days because ISE has already cleared them
        four_day_expiration = datetime.datetime.now(tz=None) - datetime.timedelta(days=4)
        df_expired = self.sessions.loc[self.sessions.index < four_day_expiration]
        if len(df_expired) > 0:
            self.sessions = self.sessions.drop(self.sessions[self.sessions['Acct-Session-Id'].isin(df_expired['Acct-Session-Id'].to_list())].index)
            log.debug(f"{self.ICONS['INFO']} Dropped {len(df_expired)} sessions > 4 days old\n{df_expired.drop(columns=RADNAD.HIDE_COLUMNS).infer_objects(copy=False).reset_index().to_string(index=False)}")

        if len(self.sessions) <= 0: return [] # No sessions to stop

        # Stop any session with a duration beyond the Session-Timeout
        responses = []
        session_expired_condition = (datetime.datetime.now(tz=None) - self.sessions.index).seconds > self.sessions['Session-Timeout']
        df_expired = self.sessions.loc[session_expired_condition]
        if len(df_expired) > 0:
            log.info(f"{self.ICONS['INFO']} Expiring {len(df_expired)} sessions ...\n{df_expired.drop(columns=RADNAD.HIDE_COLUMNS).infer_objects(copy=False).reset_index().to_string(index=False)}")
            for idx,session in df_expired.iterrows():
                # log.info(f"expired session: {type(session)} {session}")
                attrs = {
                    'Acct-Status-Type' : 'Stop',
                    'Acct-Session-Id' : session['Acct-Session-Id'],
                    'User-Name' : session['User-Name'],
                    'Calling-Station-Id' : session['Calling-Station-Id'],
                }

                # Perform the RADIUS Accounting Stop and remove the session from table if successful
                response = await self.acct_stop_by_attrs(attrs)
                responses.append(response)

            log.info(f"{self.ICONS['INFO']} Expired {len(responses)} sessions")

        return responses


async def radnad_cli() :
    """
    Parse the command line arguments
    """
    SCENARIOS = ['dot1x', 'dot1x-wired', 'wired-dot1x', 'dot1x-wireless', 'wireless-dot1x', 'mab', 'mab-wired','wired-mab', 'mab-wireless', 'wireless-mab', 'vpn', 'sessions', 'stop', 'random']

    argp = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter) # keep my format
    # argp.add_argument('-n','--number', default=0, type=int, help='the number of auths to perform', required=False)
    argp.add_argument('scenario', choices=SCENARIOS, default='dot1x', help='authentication scenario')
    argp.add_argument('-i','--id', default=RADNAD.NAS_IDENTIFIER_DEFAULT, help='NAS Identifier', required=False)
    argp.add_argument('-m','--calling', default=RADNAD.generate_mac(), help='endpoint address (MAC)', required=False)
    argp.add_argument('-d','--called', default=RADNAD.generate_mac(), help='NAS port address', required=False)
    argp.add_argument('-u','--username', default=None, help='username', required=False)
    argp.add_argument('-p','--password', default=None, help='password', required=False)
    argp.add_argument('-s','--sid', default=None, help='session ID', required=False)
    argp.add_argument('-t','--timer', action='store_true', default=False, help='time', required=False)
    argp.add_argument('-v','--verbosity', action='count', default=0, help='verbosity level', required=False)
    args = argp.parse_args()

    args.verbosity = 5 if args.verbosity > 5 else args.verbosity
    if args.verbosity:
        VERBOSITY_TO_LOGLEVEL = {
            1: 50, # CRITICAL
            2: 40, # ERROR
            3: 30, # WARNING
            4: 20, # INFO
            5: 10, # DEBUG
            0: 0   # NOTSET
        }
        log_level = VERBOSITY_TO_LOGLEVEL[int(args.verbosity)]
        log.setLevel(log_level)
        # log = logging.getLogger('radnad').setLevel(log_level)
        print(f"{RADNAD.ICONS['INFO']} Verbosity: {args.verbosity} => LOG_LEVEL: {log_level}", file=sys.stderr)

    if args.timer: start_time = datetime.datetime.now(tz=None)  # timezone aware

    # Validate options
    nas_id = args.id
    scenario = args.scenario.strip().lower() # validated by argpase choices
    scenario = random.choice(RADNAD.SCENARIOS[0:-1]) if scenario == 'random' else scenario # any but 'random'!
    calling = RADNAD.generate_ip_address() if scenario.lower() == 'vpn' else args.calling
    called = args.called
    username = args.username
    password = args.password
    nas_port_id = f"GigabitEthernet1/{random.randrange(1,48)}" if scenario.lower() in ['dot1x', 'dot1x-wired', 'wired', 'mab', 'mab-wired', 'wired-mab'] else None
    attributes = None

    env = {k:v for (k,v) in os.environ.items()} # Load environment variables
    try:
        radnad = RADNAD(name=nas_id, server=env.get('ISE_PSN', None), secret=env.get('ISE_RADIUS_SECRET', None))
        await radnad.stop_expired_sessions()

        if scenario == 'sessions':
            if args.verbosity: print(f"{RADNAD.ICONS['INFO']} List active sessions", file=sys.stderr)
            radnad.show_sessions()

        elif scenario == 'stop':
            if args.verbosity: print(f"{RADNAD.ICONS['INFO']} Stop active sessions", file=sys.stderr)
            # Filter sessions by Session-ID?
            sessions = radnad.get_sessions() if args.sid is None else radnad.get_sessions_by_id(int(args.sid))
            for idx,session in sessions.iterrows():
                if args.verbosity: print(f"{RADNAD.ICONS['INFO']} Expired Session: {session.to_list()}", file=sys.stderr)
                attrs = {
                    'Acct-Status-Type' : 'Stop',
                    'Acct-Session-Id' : session['Acct-Session-Id'],
                    'User-Name' : session['User-Name'],
                    'Calling-Station-Id' : session['Calling-Station-Id'],
                }
                response = await radnad.acct_stop_by_attrs(attrs)

        else:
            if scenario in ['dot1x', 'dot1x-wired', 'wired']:
                response= await radnad.dot1x_wired_pap(username, password, calling, called, nas_port_id=nas_port_id, attributes=None)
            elif scenario in ['wireless', 'dot1x-wireless', 'wireless-dot1x']:
                response= await radnad.dot1x_wireless_pap(username, password, calling, called, attributes=None)
            elif scenario in ['mab', 'mab-wired', 'wired-mab']:
                response= await radnad.mab_wired(calling, called, nas_port_id=nas_port_id, attributes=None)
            elif scenario in ['mab-wireless', 'wireless-mab']:
                response= await radnad.mab_wireless(calling, called, attributes)
            elif scenario == 'vpn':
                response= await radnad.vpn(username, password, calling, called, attributes)
            else:
                sys.exit(f"Unknown scenario: {scenario}")

            if response is not None: radnad.show_sessions()

    except TimeoutError as e:
        log.error(f"No Reply. Timeout/Dropped:\n{e}")   # No content!
        print(f"✖ No Reply. Timeout/Dropped:\n{e}", file=sys.stderr)   # No content!
    except Exception as e:
        tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
        print(f"✖ {e.__class__} | {tb_text}", file=sys.stderr)

    if args.timer : print(f"⏲ {(datetime.datetime.now(tz=None).timestamp() - start_time.timestamp()):0.3f} seconds")


if __name__ == '__main__':
    """
    Execute when the module is not initialized from an import statement.
    """
    asyncio.run(radnad_cli(), debug=False) # invoke as async
    sys.exit(0) # 0 is ok

