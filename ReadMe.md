# README.md

RADNADS (**RAD**IUS **N**etwork **A**ccess **D**evice **S**imulator) is a collection of Python scripts used to simulate basic RADIUS network traffic for testing and simple simulations of live network operations. It relies on the [`radclient`](https://freeradius.org/documentation/freeradius-server/4.0.0/reference/man/radclient.html) utility to perform the actual RADIUS authentication and accounting transactions with a RADIUS server like Cisco Identity Services Engine (ISE).

The were created to allow the user to quickly and easily:

- simulate a single PAP/CHAP authentication for 802.1X (dot1x) wired or wireless, MAB wired or wireless, and VPN connections
- automatically start a RADIUS accounting session (`radclient` only does a single authentication *or* accounting per invocation)
- stop expired sessions (based on Session-Timeout, as returned by the RADIUS server)
- randomly Disconnect random sessions, like the real world
- use asynchronous timers to periodically [re]authenticate users and endpoints and clear expired sessions

Limitations:

- the `radclient` utility only 


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

Attempts to create a single RADIUS session as a RADIUS client by performing authentication and accounting requests for an endpoint or user. Many default methods and access types are provided by default but you may always customize the actual RADIUS attributes sent to simulate any request or network device type.

`radnad.py` may be invoked using the CLI or as a Python class from your own custom script like `radnad-periodic.py`. Use `radnad.py --help ` for CLI usage examples with the commands and options.

```sh
radnad.py [-h] [-i ID] [-m CALLING] [-d CALLED] [-u USERNAME] [-p PASSWORD] [-s SID] [-t] [-v]
                 {dot1x,dot1x-wired,wired-dot1x,dot1x-wireless,wireless-dot1x,mab,mab-wired,wired-mab,mab-wireless,wireless-mab,vpn,sessions,stop,random}
```

## radnad-periodic.py

This utilizes the `radnad.py`'s `RADNAD` class to simulate a real network device by periodically generating RADIUS requests, expiring sessions based on their timeout values, and randomly disconnects others. It may be extended to support additional scenarios, endpoints, and users or customized to vary the frequency in which they happen to suit the scale of your desired environment.

Simply run it with :
```sh
radnad-periodic.py
```
