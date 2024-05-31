#!/usr/bin/env python3
"""
A Python client that periodically creates and disconnects RADIUS sessions using the `radnad.py` class.

Usage:
    radnad-periodic.py

Requires setting the these environment variables using the `export` command:
  export ISE_PSN='1.2.3.4'              # hostname or IP of an ISE PSN (policy service node)
  export ISE_RADIUS_SECRET='C1sco12345' # RADIUS server pre-shared key

You may add these export lines to a text file and load with `source`:
  source ise-env.sh

"""
__author__ = "Thomas Howard"
__email__ = "thomas@cisco.com"
__license__ = "MIT - https://mit-license.org/"

import asyncio
import datetime
import logging
import radnad
import os
import random
import signal
import sys
import time
import traceback
import tracemalloc
tracemalloc.start()

DT_ISO8601 = "%Y-%m-%d %H:%M:%S"        # Ex: 2005-08-15 15:52:01
# logging.basicConfig(filename='radnad.log', format=LOG_FORMAT, datefmt=DT_ISO8601)
LOG_FORMAT = '%(asctime)s | %(levelname)s | %(message)s'
logging.basicConfig(filename='-', format=LOG_FORMAT, datefmt=DT_ISO8601) # log to stdout by default
log = logging.getLogger()
log.setLevel(logging.INFO)


def iso_timestamp(ts:float=0) -> str:
    """
    Returns an ISO-formatted timestamp string.
    :param ts (float) : a timestamp representing the date and time since the epoch (1699209810.552214).
    """
    ts = datetime.datetime.now(tz=None).timestamp() if ts == 0 else ts
    return time.strftime(DT_ISO8601, time.localtime(ts))


async def periodic_task(period:int=60.0, delay:int=0):
    """
    A task that runs every period after the specified delay.
    :param name (str) : a task name
    :param period (int) : the periodic interval, in seconds
    :param delay (int) : the delay, in seconds, to wait before starting
    """
    if delay > 0:
        print(f"{iso_timestamp()} {RADNAD.ICONS['PLAY']} periodic_task(period={period}s, delay={delay}s", file=sys.stderr)
        log.info(f"{RADNAD.ICONS['PLAY']} periodic_task(period={period}s, delay={delay}s")
        await asyncio.sleep(delay)  # suspend task
    while True:
        try:
            await asyncio.sleep(period)  # suspend task
            print(f"{iso_timestamp()} {RADNAD.ICONS['PLAY']} periodic_task({period}s) {RADNAD.ICONS['WAIT']} {period}s", file=sys.stderr)
            log.debug(f"{RADNAD.ICONS['PLAY']} periodic_task({period}s) {RADNAD.ICONS['WAIT']} {period}s")
            # do stuff
        except Exception as e:
            tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
            print(f"{RADNAD.ICONS['FAIL']} periodic_task() {e.__class__} | {tb_text}", file=sys.stderr)
            log.critical(f"{iso_timestamp()} finally: periodic_task()")


async def random_task(min:int=1, max:int=3600, delay:int=0):
    """
    A randomly occuring task.
    :param name (str) : a task name
    :param delay (int) : the delay, in seconds, to wait before starting
    :param min (int) : the minimal time, in seconds, between running the task.
    :param max (int) : the maximum time, in seconds, between running the task.
    """
    if delay > 0: await asyncio.sleep(delay)  # suspend task
    sleep_time = random.randint(min, max)
    while True:
        try:
            await asyncio.sleep(sleep_time)  # suspend task
            sleep_time = random.randint(min, max)
            print(f"{iso_timestamp()} {RADNAD.ICONS['PLAY']} random_task({min}-{max}s) {RADNAD.ICONS['WAIT']} {sleep_time}s", file=sys.stderr)
            log.debug(f"{RADNAD.ICONS['PLAY']} random_task({min}-{max}s) {RADNAD.ICONS['WAIT']} {sleep_time}s")
            # do stuff
        except Exception as e:
            tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
            print(f"{RADNAD.ICONS['FAIL']} random_task() {e.__class__} | {tb_text}", file=sys.stderr)
            log.critical(f"{iso_timestamp()} finally: random_task()")


async def stop_expired_sessions(radnad:radnad.RADNAD=None, period:int=60.0):
    """
    A randomly occuring task.
    :param name (str) : a task name
    :param delay (int) : the delay, in seconds, to wait before starting
    :param min (int) : the minimal time, in seconds, between running the task.
    :param max (int) : the maximum time, in seconds, between running the task.
    """
    responses = await radnad.stop_expired_sessions()
    if len(responses) > 0:
        print(f"{iso_timestamp()} {radnad.ICONS['STOP']} stop_expired_sessions({period}s): {len(responses)} sessions", file=sys.stderr)
    while True:
        await asyncio.sleep(period)  # suspend task
        # print(f"{iso_timestamp()} {radnad.ICONS['PLAY']} stop_expired_sessions() {radnad.ICONS['WAIT']} {period}s", file=sys.stderr)
        log.debug(f"{radnad.ICONS['PLAY']} stop_expired_sessions() {radnad.ICONS['WAIT']} {period}s")
        try:
            responses = await radnad.stop_expired_sessions()
            # 🚧 ToDo: Display expired sessions
            if len(responses) > 0:
                print(f"{iso_timestamp()} {radnad.ICONS['STOP']} stop_expired_sessions({period}s): {len(responses)} sessions", file=sys.stderr)

        except TimeoutError as e:
            log.error(f"No Reply. Timeout/Dropped:\n{e}")   # No content!
            print(f"{radnad.ICONS['WARN']} No Reply. Timeout/Dropped:\n{e}")   # No content!
        except Exception as e:
            tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
            print(f"{radnad.ICONS['FAIL']} {e.__class__} | {tb_text}", file=sys.stderr)
            log.critical(f"{iso_timestamp()} finally: stop_expired_sessions()")


async def show_sessions(radnad:radnad.RADNAD=None, period:int=60.0):
    """
    A randomly occuring task.
    :param name (str) : a task name
    :param delay (int) : the delay, in seconds, to wait before starting
    :param min (int) : the minimal time, in seconds, between running the task.
    :param max (int) : the maximum time, in seconds, between running the task.
    """
    radnad.show_sessions()
    while True:
        await asyncio.sleep(period)  # suspend task
        try:
            # radnad.show_sessions()
            print(f"{iso_timestamp()} {radnad.ICONS['PLAY']} show_sessions({period}s) {radnad.get_session_count()} sessions", file=sys.stderr)
        except Exception as e:
            tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
            print(f"{radnad.ICONS['FAIL']} {e.__class__} | {tb_text}", file=sys.stderr)
            log.critical(f"{radnad.ICONS['FAIL']} show_sessions() {e.__class__} | {tb_text}")


async def random_auth(radnad:radnad.RADNAD=None, usernames:list=None, scenarios:list=None, min:int=1, max:int=3600, delay:int=0):
    """
    A randomly occuring task.
    :param name (str) : a task name
    :param delay (int) : the delay, in seconds, to wait before starting
    :param min (int) : the minimal time, in seconds, between running the task.
    :param max (int) : the maximum time, in seconds, between running the task.
    """
    if delay > 0: 
        print(f"{iso_timestamp()} {radnad.ICONS['PAUSE']} random_auth(delay={delay}s)", file=sys.stderr)
        await asyncio.sleep(delay)  # suspend task
    while True:
        try:
            sleep_time = random.randint(min, max)
            print(f"{iso_timestamp()} {radnad.ICONS['PLAY']} random_auth({min}-{max}s): {radnad.ICONS['WAIT']} {sleep_time}s", file=sys.stderr)
            # log.debug(f"{radnad.ICONS['WAIT']} random_auth({min}-{max}s): {sleep_time}s")
            await asyncio.sleep(sleep_time)  # suspend task

            scenario = random.choice(scenarios)
            calling = radnad.generate_ip_address() if scenario.lower() == 'vpn' else radnad.generate_mac()
            called = radnad.generate_mac()
            called += ":corp" if scenario.lower() == 'dot1x-wireless' else ''
            called += ":iot" if scenario.lower() == 'mab-wireless' else ''
            username = random.choice(usernames)
            password = 'C1sco12345'
            nas_port_id = f"GigabitEthernet1/{random.randrange(1,48)}"

            if scenario == 'dot1x':
                response= await radnad.dot1x_wired_pap(username, password, calling, called, nas_port_id=nas_port_id, attributes=None)
            elif scenario == 'dot1x-wired':
                response= await radnad.dot1x_wired_pap(username, password, calling, called, nas_port_id=nas_port_id, attributes=None)
            elif scenario == 'wireless':
                response= await radnad.dot1x_wireless_pap(username, password, calling, called)
            elif scenario == 'dot1x-wireless':
                response= await radnad.dot1x_wireless_pap(username, password, calling, called)
            elif scenario == 'mab':
                response= await radnad.mab_wired(calling, called, nas_port_id=nas_port_id, attributes=None)
            elif scenario == 'mab-wired':
                response= await radnad.mab_wired(calling, called, nas_port_id=nas_port_id, attributes=None)
            elif scenario == 'mab-wireless':
                response= await radnad.mab_wireless(calling, called)
            elif scenario == 'vpn':
                response= await radnad.vpn(username, password, calling, called)
            else:
                sys.exit(f"Unknown scenario: {scenario}")

            # details = f"{scenario} calling:{calling} called:{called}"
            # details += f" {username}" if not scenario.startswith('mab') else ''
            details = scenario + (f" {username} " if not scenario.startswith('mab') else ' ') + f"calling:{calling} called:{called}"
            # icon = ICONS['PLAY'] if response.
            # if response.rsp_type == RADIUSResponse.ACCESS_ACCEPT:
            #     # Authentication Passed
            #     log.info(f"{response.RESPONSE_ICONS[response.rsp_type]} {response.rsp_type} {response.__dict__}")
            # icon = ICONS['UNKNOWN'] RADIUSResponse.ACCESS_ACCEPT

            print(f"{iso_timestamp()} {radnad.ICONS['PLAY']} random_auth({min}-{max}s): {details}", file=sys.stderr)
            log.debug(f"{radnad.ICONS['PLAY']} random_auth({min}-{max}s) {details} {radnad.ICONS['PLAY']} {sleep_time}s")
 
        except Exception as e:
            tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
            print(f"{radnad.ICONS['FAIL']} {e.__class__} | {tb_text}", file=sys.stderr)
            log.critical(f"{radnad.ICONS['FAIL']} random_auth() {e.__class__} | {tb_text}")


async def random_disconnect(radnad:radnad.RADNAD=None, n=1, min:int=30, max:int=3600, delay:int=300):
    """
    A randomly occuring task.
    :param name (str) : a task name
    :param delay (int) : the delay, in seconds, to wait before starting
    :param min (int) : the minimal time, in seconds, between running the task.
    :param max (int) : the maximum time, in seconds, between running the task.
    """
    if delay > 0: 
        print(f"{iso_timestamp()} {radnad.ICONS['PAUSE']} random_disconnect(delay={delay}s)", file=sys.stderr)
        await asyncio.sleep(delay)  # suspend task
    while True:
        try:
            sleep_time = random.randint(min, max)
            print(f"{iso_timestamp()} {radnad.ICONS['PLAY']} random_disconnect({min}-{max}s): {radnad.ICONS['WAIT']} {sleep_time}s", file=sys.stderr)
            # log.debug(f"{radnad.ICONS['WAIT']} random_disconnect({min}-{max}s): {sleep_time}s")
            await asyncio.sleep(sleep_time)  # suspend task
            sessions = radnad.get_sessions()
            if len(sessions) > 0:
                sessions = sessions.sample(n)
                # print(f"random_disconnect(): {sessions.loc[sessions.first_valid_index()].to_dict()}")
                for idx,session in sessions.iterrows():
                    # print(f"random_disconnect(): {type(session)} {session}")
                    # The minimum attributes required by ISE for an Accounting Stop are:
                    # - User-Name           # Does not like MAC for MAB
                    # - Calling-Station-Id
                    # - Acct-Status-Type    # Must be 'Stop'
                    # - Acct-Session-Id     # May be anything but must include something
                    attrs = {
                        'Acct-Status-Type' : 'Stop',
                        'Acct-Session-Id' : session['Acct-Session-Id'],
                        'User-Name' : session['User-Name'],
                        'Calling-Station-Id' : session['Calling-Station-Id'],
                    }
                    response = await radnad.acct_stop_by_attrs(attrs)
                    print(f"{iso_timestamp()} {radnad.ICONS['STOP']} random_disconnect({min}-{max}s): {attrs.get('User-Name')} {attrs.get('Calling-Station-Id')} {attrs.get('Acct-Session-Id')}")


        except Exception as e:
            tb_text = '\n'.join(traceback.format_exc().splitlines()[1:]) # remove 'Traceback (most recent call last):'
            print(f"{radnad.ICONS['FAIL']} {e.__class__} | {tb_text}", file=sys.stderr)
            log.critical(f"{radnad.ICONS['FAIL']} random_disconnect() {e.__class__} | {tb_text}")


async def radnad_periodic_tasks():
    """
    """
    env = {k:v for (k,v) in os.environ.items()} # Load environment variables
    nad = radnad.RADNAD(server=env.get('ISE_PSN', None), secret=env.get('ISE_RADIUS_SECRET', None))

    USERNAMES = ['hayley', 'brad', 'paul', 'arthur', 'ryan', 'anita', 'cathy', 'victoria', 'sarah', 'ruby', 'carol', 'alex', 'armando', 'sergio', 'wilfriend', 'anna', 'adriana', 'maria', 'nicolina', 'wan', 'dong', 'yan', 'wu', 'ali', 'yasmin', 'rahul', 'amar', 'neha', 'aang', 'tyrice', 'dace', 'karah', 'eilane', 'alex', 'jane', 'paula', 'michael', 'wndy', 'hr', 'finance', 'sales', 'marketing', 'it', 'security', 'engineering', 'design', 'manufacturing', 'ceo', 'cto', 'cio', 'ciso', 'cfo','thomas', 'charlie', 'joff', 'paul', 'scott', 'devi', 'jerome', 'pavan', 'srilatha', 'jacob', 'ben', 'taylor',]
    SCENARIOS = ['dot1x', 'dot1x-wired', 'wireless', 'dot1x-wireless', 'mab-wired', 'mab-wireless', 'vpn']

    try:
        tasks = [
            stop_expired_sessions(nad, period=5),
            show_sessions(nad), # default 60s
            random_auth(nad, usernames=USERNAMES, scenarios=SCENARIOS, min=10, max=60),
            random_disconnect(nad, min=60, max=300, delay=300),

            # 💡ToDo: some more periodic functions to implement
            # random_dot1x_wireless(nad, min=60, max=300, delay=300)
            # random_dot1x_wired(nad, min=60, max=300, delay=300)
            # random_vpn(nad, min=60, max=300, delay=300)
            # random_mab(nad, min=60, max=300, delay=300)
            # random_guest(nad, min=60, max=300, delay=300)
            # authenticate_all_iot()
            # random_disconnects(rate=1)
            # authenticate_phones()
            # vpn_spray(nad, interval=1d count=5000, delay=300)

            # Generic test functions
            # periodic_task(period=10, delay=4),
            # periodic_task(period=30),
            # periodic_task(period=60, delay=60),
            # periodic_task(period=120),
            # periodic_task(period=180),
            # random_task(min=5, max=60, delay=0),
        ]

        # all coroutines are automatically scheduled as a Task(s)
        awaitables = await asyncio.gather(*tasks, return_exceptions=False) # use * to unpack list items

        log.info(f"awaitables : {awaitables}")

    except asyncio.CancelledError:
        pass    # do_cleanup()


if __name__ == '__main__' :

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    main_task = asyncio.ensure_future( radnad_periodic_tasks() )

    # Handle CTRL+C interrupts gracefully
    from signal import SIGINT, SIGTERM
    for signal in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(signal, main_task.cancel)
    try:
        loop.run_until_complete(main_task)
    finally:
        # loop.run_until_complete(srv.wait_closed())
        # loop.run_until_complete(app.shutdown())
        # loop.run_until_complete(handler.finish_connections(shutdown_timeout))
        # loop.run_until_complete(app.cleanup())
        loop.close()
