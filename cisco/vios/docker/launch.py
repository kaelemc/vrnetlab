#!/usr/bin/env python3
import datetime
import logging
import os
import re
import signal
import sys

import vrnetlab
from scrapli.driver.core import IOSXEDriver

STARTUP_CONFIG_FILE = "/config/startup-config.cfg"


def handle_SIGCHLD(_signal, _frame):
    os.waitpid(-1, os.WNOHANG)


def handle_SIGTERM(_signal, _frame):
    sys.exit(0)


signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)


logging.Logger.trace = trace


class VIOS_vm(vrnetlab.VM):
    def __init__(self, hostname: str, username: str, password: str, conn_mode: str):
        disk_image = None
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e
        if not disk_image:
            raise Exception("No disk image found")

        super(VIOS_vm, self).__init__(
            username=username,
            password=password,
            disk_image=disk_image,
            smp="1",
            ram=512,
            driveif="virtio",
            use_scrapli=True,
        )

        self.hostname = hostname
        self.conn_mode = conn_mode
        # device supports up to 16 interfaces (1 management interface + 15 data interfaces)
        self.num_nics = 15
        self.running = False
        self.spins = 0

    def bootstrap_spin(self):
        if self.spins > 300:
            # too many spins with no result -> give up
            self.stop()
            self.start()
            return

        (ridx, match, res) = self.con_expect(
            [
                rb"Would you like to enter the initial configuration dialog\? \[yes/no\]:",
                b"Press RETURN to get started!",
                b"Router>",
            ],
        )

        if match:
            if ridx == 0:
                self.logger.info("Skipping initial configuration dialog")
                self.wait_write("no", wait=None)
            elif ridx == 1:
                self.logger.info("Entering user EXEC mode")
                for _ in range(3):
                    self.wait_write("\r", wait=None)
            elif ridx == 2:
                self.apply_config()

                # startup time
                startup_time = datetime.datetime.now() - self.start_time
                self.logger.info(f"Startup complete in: {startup_time}")
                # mark as running
                self.running = True
                return

        # no match, if we saw some output from the router it's probably
        # booting, so let's give it some more time
        if res != b"":
            self.write_to_stdout(res)
            # reset spins if we saw some output
            self.spins = 0

        self.spins += 1
        return

    def apply_config(self):
        scrapli_timeout = os.getenv("SCRAPLI_TIMEOUT", vrnetlab.DEFAULT_SCRAPLI_TIMEOUT)
        self.logger.info(
            f"Scrapli timeout is {scrapli_timeout}s (default {vrnetlab.DEFAULT_SCRAPLI_TIMEOUT}s)"
        )

        # init scrapli
        vios_scrapli_dev = {
            "host": "127.0.0.1",
            "auth_bypass": True,
            "auth_strict_key": False,
            "timeout_socket": scrapli_timeout,
            "timeout_transport": scrapli_timeout,
            "timeout_ops": scrapli_timeout,
        }

        v4_mgmt_address = vrnetlab.cidr_to_ddn(self.mgmt_address_ipv4)

        vios_config = f"""hostname {self.hostname}
username {self.username} privilege 15 password {self.password}
ip domain-name example.com
no ip domain-lookup
!
line con 0
logging synchronous
exec timeout 0 0
!
line vty 0 4
logging synchronous
login local
transport input all
exec timeout 0 0
!
ipv6 unicast-routing
!
vrf definition clab-mgmt
description Containerlab management VRF (DO NOT DELETE)
address-family ipv4
exit
address-family ipv6
exit
exit
!
ip route vrf clab-mgmt 0.0.0.0 0.0.0.0 {self.mgmt_gw_ipv4}
ipv6 route vrf clab-mgmt ::/0 {self.mgmt_gw_ipv6}
!
interface GigabitEthernet0/0
description Containerlab management interface
vrf forwarding clab-mgmt
ip address {v4_mgmt_address[0]} {v4_mgmt_address[1]}
ipv6 address {self.mgmt_address_ipv6}
no shut
exit
!
crypto key generate rsa modulus 2048
ip ssh version 2
!
netconf ssh
netconf max-sessions 16
snmp-server community public rw
!
no banner exec
no banner login
no banner incoming
!   
"""

        con = IOSXEDriver(**vios_scrapli_dev)
        con.commandeer(conn=self.scrapli_tn)

        if os.path.exists(STARTUP_CONFIG_FILE):
            self.logger.info("Startup configuration file found")
            with open(STARTUP_CONFIG_FILE, "r") as config:
                vios_config += config.read()
        else:
            self.logger.warning("User provided startup configuration is not found.")

        res = con.send_configs(vios_config.splitlines())
        res += con.send_commands(["write memory"])

        for response in res:
            self.logger.info(f"CONFIG:{response.channel_input}")
            self.logger.info(f"RESULT:{response.result}")

        # close the scrapli connection
        con.close()


class VIOS(vrnetlab.VR):
    def __init__(self, hostname: str, username: str, password: str, conn_mode: str):
        super(VIOS, self).__init__(username, password)
        self.vms = [VIOS_vm(hostname, username, password, conn_mode)]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable trace level logging",
        default=os.getenv("TRACE", "false").lower() == "true",
    )
    parser.add_argument(
        "--username", help="Username", default=os.getenv("USERNAME", "admin")
    )
    parser.add_argument(
        "--password", help="Password", default=os.getenv("PASSWORD", "admin")
    )
    parser.add_argument(
        "--hostname", help="Router hostname", default=os.getenv("HOSTNAME", "vios")
    )
    parser.add_argument(
        "--connection-mode",
        help="Connection mode to use in the datapath",
        default=os.getenv("CONNECTION_MODE", "tc"),
    )
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    vr = VIOS(
        hostname=args.hostname,
        username=args.username,
        password=args.password,
        conn_mode=args.connection_mode,
    )
    vr.start()
