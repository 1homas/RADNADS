#!/usr/bin/env python3
"""
Examples of how to use the `radnad.py` Python wrapper to performs RADIUS authentications in your scripts.

Usage:
    radnad-client-examples.py

Requires setting the these environment variables using the `export` command:
  export ISE_PSN='1.2.3.4'              # hostname or IP of an ISE PSN (policy service node)
  export ISE_RADIUS_SECRET='C1sco12345' # RADIUS server pre-shared key

You may add these export lines to a text file and load with `source`:
  source ise-env.sh

"""
__author__ = "Thomas Howard"
__email__ = "thomas@cisco.com"
__license__ = "MIT - https://mit-license.org/"

from multidict import MultiDict
import asyncio
import os
from radnad import RADNAD

async def main(): # async/await required to use RADNAD 

    env = {k:v for (k,v) in os.environ.items()} # Load environment variables

    # Define some variables for authentications
    username = 'thomas'
    password ='C1sco12345'
    wireless_corp = 'C0:FF:EE:EE:CA:FE:corp'
    wireless_iot = 'C0:FF:EE:EE:CA:FE:iot'

    # Create RADNAD instance
    radnad = RADNAD(name='simulator', server=env.get('ISE_PSN', None), secret=env.get('ISE_RADIUS_SECRET', None))

    # Call RADIUS convenience functions to do authentication + accounting
    response = await radnad.dot1x_wired_pap(username, password, calling=RADNAD.generate_mac())
    response = await radnad.dot1x_wireless_pap(username, password, calling=RADNAD.generate_mac(), called=wireless_corp)
    response = await radnad.mab_wired(calling='12:34:56:78:90:AB', called=RADNAD.generate_mac(), nas_port_id='GigabitEthernet1/1')
    response = await radnad.mab_wireless(calling='12:34:56:78:90:AB', called=wireless_iot)
    response = await radnad.vpn(username, password, calling='10.1.2.3')

    # You may even build your own RADIUS attribute dictionary to request a session
    mac = RADNAD.generate_mac()
    attrs = MultiDict({
        'Service-Type': 'Call-Check',
        'NAS-Port-Type': 'Ethernet',
        'User-Name': mac,
        'User-Password': mac,
        'Calling-Station-Id': mac,
        'Called-Station-Id': RADNAD.generate_mac(),
    })
    response = await radnad.session(attrs)

    # Or you may use the same attributes and call radnad.auth() and radnad.acct() separately to start a session
    response = await radnad.auth(attrs)      # returns RADIUSResponse
    response = await radnad.acct(response)   # returns RADIUSResponse

    # Dump your session list
    radnad.show_sessions()

if __name__ == '__main__':
    """
    Execute when the module is not initialized from an import statement.
    """
    asyncio.run( main() ) # invoke as async

