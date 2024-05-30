# RADNADS (RADIUS Network Access Device Simulator) 

RADNADS (**RAD**IUS **N**etwork **A**ccess **D**evice **S**imulator) is a collection of Python scripts used to simulate basic RADIUS network traffic for testing and simple simulations of live network operations. It relies on the [`radclient`](https://freeradius.org/documentation/freeradius-server/4.0.0/reference/man/radclient.html) utility to perform the actual RADIUS authentication and accounting transactions with a RADIUS server like Cisco Identity Services Engine (ISE).

The were created to allow the user to quickly and easily:

- simulate a single PAP/CHAP authentication for 802.1X (dot1x) wired or wireless, MAB wired or wireless, and VPN connections
- automatically start a RADIUS accounting session (`radclient` only does a single authentication *or* accounting per invocation)
- stop expired sessions (based on Session-Timeout, as returned by the RADIUS server)
- randomly Disconnect random sessions, like the real world
- use asynchronous timers to periodically [re]authenticate users and endpoints and clear expired sessions

Limitations:

- all simulated requests will come from the same source IP and therefore appear in ISE as a single network device becasue the `radclient` utility has no option to specify different, local, virtual, host IPs

## Installation

Clone this repository:

```sh
git clone https://github.com/1homas/RADNADS
cd RADNADS
```

Install the `radclient` utility which is most easily obtained as part of the [freeradius](https://freeradius.org/) software package. 

Linux may use `freeradius-utils`:

```sh
apt update
apt install freeradius-utils
```

macOS does not have the `freeradius-utils` package so you must install the full `freeradius-server` package:

```sh
brew update
brew install freeradius-server
```

Verify installation and path:

```sh
which radclient
```

Create a Python virtual environment to run the scripts:

```sh
pipenv install                 # install a Python virtual environment
pipenv install -r requirements # install the required packages
pipenv shell                   # invoke the Python virtual environment
```

Ensure the required environment variables are set using the `export` command:

```sh
export ISE_PSN='1.2.3.4'              # hostname or IP of an ISE PSN (policy service node)
export ISE_RADIUS_SECRET='C1sco12345' # RADIUS server pre-shared key
```

You may add these export lines to a `.env` or `*.sh` text file and load with `source`:

```sh
source ./.env
source ~/.secrets/ise-env.sh
```


## radnad.py

Attempts to create a single RADIUS session as a RADIUS client by performing authentication and accounting requests for an endpoint or user. Many default methods and access types are provided by default but you may always customize the actual RADIUS attributes sent to simulate any request or network device type. It will persist RADIUS sessions to a `radnad.sessions.csv` file to track active sessions over multiple invocations.

Use `radnad.py --help ` for CLI usage examples with the commands and options. `radnad.py` may be invoked using the CLI or as a Python class from your own custom script like `radnad-periodic.py`.


### MAB (MAC Authentication Bypass)

By default, a MAB request will probably *fail* unless you have an explicit ISE authentication rule to allow MAB with any random MAC address to connect:

```sh
❱ radnad.py mab
✖ MAB A9-20-82-FF-3D-C6 A9-20-82-FF-3D-C6 (0) -: Expected Access-Accept got Access-Reject
```

If you have a specific MAC address to use with MAB, use the `--calling` attribute to specify the RADIUS `Calling-Station-Id`:

```sh
❱ radnad.py mab --calling A9-20-82-FF-3D-C6
All Sessions by Duration
              Timestamp Method Status         User-Name Calling-Station-Id Framed-IP-Address  Session-Timeout Acct-Session-Id Called-Station-Id NAS-Port-Type         NAS-Port-Id NAS-Port NAS-Identifier  Duration
2024-05-30 14:11:15.124    MAB  Start A9-20-82-FF-3D-C6  A9-20-82-FF-3D-C6      84.187.5.121             3600              53 21-73-BD-32-EC-0F      Ethernet GigabitEthernet1/23       32         RADNAD         0
```

### 802.1X

This assumes you have the user and password defined in the RADIUS server. The `dot1x` scenario will assume a wired connection unless you explicitly choose `dot1x-wireless`:

```sh
❱ radnad.py dot1x -u thomas -p C1sco12345
All Sessions by Duration
              Timestamp Method Status         User-Name Calling-Station-Id Framed-IP-Address  Session-Timeout Acct-Session-Id      Called-Station-Id   NAS-Port-Type         NAS-Port-Id NAS-Port NAS-Identifier  Duration
2024-05-30 14:15:06.932 802.1X  Start            thomas  1D-31-57-B0-C8-31     14.224.109.82             3600              47      62-77-63-35-79-37        Ethernet GigabitEthernet1/31        5         RADNAD         0
```

A wireless 802.1X session is easy to create and customize with a specific access point MAC and SSID using the `--called` option to represent the RADIUS `Called-Station-Id`:

```sh
❱ radnad.py dot1x-wireless -u thomas -p C1sco12345 --called 11:22:33:44:55:66:corp
All Sessions by Duration
              Timestamp Method Status         User-Name Calling-Station-Id Framed-IP-Address  Session-Timeout Acct-Session-Id      Called-Station-Id   NAS-Port-Type         NAS-Port-Id NAS-Port NAS-Identifier  Duration
2024-05-30 14:19:17.327 802.1X  Start            thomas  BA-04-31-0C-D4-C3     51.56.148.203             3600              48 11:22:33:44:55:66:corp Wireless-802.11   BA-04-31-0C-D4-C3      120         RADNAD         0
```

### VPN (Virtual Private Network)

VPN sessions are just as easy to create:

```sh
❱ radnad.py vpn -u thomas -p C1sco12345
All Sessions by Duration
              Timestamp Method Status         User-Name Calling-Station-Id Framed-IP-Address  Session-Timeout Acct-Session-Id      Called-Station-Id   NAS-Port-Type         NAS-Port-Id NAS-Port NAS-Identifier  Duration
2024-05-30 14:34:15.929    VPN  Start            thomas    131.210.181.190       19.131.5.67             3600              50      E5-FD-AD-29-BF-7B         Virtual     131.210.181.190     2741         RADNAD         0
```

## radnad-periodic.py

This utilizes the `radnad.py`'s `RADNAD` class to simulate a real network device by periodically generating RADIUS requests, expiring sessions based on their timeout values, and randomly disconnects others. It may be extended to support additional scenarios, endpoints, and users or customized to vary the frequency in which they happen to suit the scale of your desired environment.

Simply run it with `radnad-periodic.py` and it will continue to run indefinitely until you press Ctrl+C:
```sh
❱ radnad-periodic.py
2024-05-30 15:51:41 ▶ random_auth(10-60s): ⏱ 42s
2024-05-30 15:51:41 ⏸ random_disconnect(delay=300s)
2024-05-30 15:52:23 ▶ random_auth(10-60s): mab-wireless calling:67-A6-C7-32-7F-1D called:95-07-97-40-6A-20:iot
2024-05-30 15:52:23 ▶ random_auth(10-60s): ⏱ 12s
2024-05-30 15:52:35 ▶ random_auth(10-60s): dot1x-wireless aang calling:79-57-E9-91-69-71 called:CD-62-0B-C0-D3-FE:corp
2024-05-30 15:52:35 ▶ random_auth(10-60s): ⏱ 43s
2024-05-30 15:52:41 ▶ show_sessions(60.0s) 2 sessions
```
