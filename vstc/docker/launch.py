#!/usr/bin/env python3

import datetime
import logging
import os
import re
import signal
import subprocess
import sys
from time import sleep

import vrnetlab

def handle_SIGCHLD(signal, frame):
    os.waitpid(-1, os.WNOHANG)


def handle_SIGTERM(signal, frame):
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


class STC_vm(vrnetlab.VM):
    def __init__(self, hostname, username, password, nics, conn_mode, install_mode=False):
        for e in os.listdir("/"):
            if re.search(".qcow2$", e):
                disk_image = "/" + e

        self._static_mgmt_mac = True

        super(STC_vm, self).__init__(
            username, password, disk_image=disk_image, use_scrapli=True
        )

        self.num_nics = nics
        self.hostname = hostname
        self.conn_mode = conn_mode
        self.nic_type = "virtio-net-pci"

    def bootstrap_spin(self):
        """This function should be called periodically to do work."""

        if self.spins > 600:
            # too many spins with no result ->  give up
            self.stop()
            self.start()
            return

        self.write_to_stdout(self.scrapli_tn.channel.read())
        # (ridx, match, res) = self.con_expect(
        #     [b"CVAC-4-CONFIG_DONE", b"Press RETURN to get started!"]
        # )
        # if match:  # got a match!
        #     if ridx == 0 and not self.install_mode:  # configuration applied
        #         self.logger.info("CVAC Configuration has been applied.")
        #         # close telnet connection
        #         self.scrapli_tn.close()
        #         # startup time?
        #         startup_time = datetime.datetime.now() - self.start_time
        #         self.logger.info("Startup complete in: %s", startup_time)
        #         # mark as running
        #         self.running = True
        #         return
        #     elif ridx == 1:  # IOSXEBOOT-4-FACTORY_RESET
        #         if self.install_mode:
        #             install_time = datetime.datetime.now() - self.start_time
        #             self.logger.info("Install complete in: %s", install_time)
        #             self.running = True
        #             return

        # # no match, if we saw some output from the router it's probably
        # # booting, so let's give it some more time
        # if res != b"":
        #     self.write_to_stdout(res)
        #     # reset spins if we saw some output
        #     self.spins = 0

        # self.spins += 1

        return

class STC(vrnetlab.VR):
    def __init__(self, hostname, username, password, nics, conn_mode):
        super(STC, self).__init__(username, password)
        self.vms = [STC_vm(hostname, username, password, nics, conn_mode)]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        "--trace", action="store_true", help="enable trace level logging"
    )
    parser.add_argument("--username", default="admin", help="Username")
    parser.add_argument("--password", default="spt_admin", help="Password")
    parser.add_argument("--hostname", default="stc", help="Hostname")
    parser.add_argument("--nics", type=int, default=31, help="Number of NICS")
    parser.add_argument(
        "--connection-mode",
        default="vrxcon",
        help="Connection mode to use in the datapath",
    )
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    vr = STC(
        args.hostname,
        args.username,
        args.password,
        args.nics,
        args.connection_mode,
    )
    vr.start()
