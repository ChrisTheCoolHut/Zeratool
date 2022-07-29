import os
import pytest
import random
import multiprocessing
import subprocess
import shlex
from shutil import which

os.environ["PWNLIB_NOTERM"] = "1"
from zeratool import overflowDetector
from zeratool import overflowExploiter
from zeratool import overflowExploitSender
from zeratool import winFunctionDetector
from zeratool import protectionDetector
from zeratool import overflowRemoteLeaker

from contextlib import redirect_stdout, redirect_stderr, contextmanager, ExitStack


@contextmanager
def suppress(out=True, err=False):
    with ExitStack() as stack:
        with open(os.devnull, "w") as null:
            if out:
                stack.enter_context(redirect_stdout(null))
            if err:
                stack.enter_context(redirect_stderr(null))
            yield


def test_detect_32():
    with suppress():
        test_file = "tests/bin/bof_win_32"
        input_type = "STDIN"
        pwn_type = overflowDetector.checkOverflow(test_file, inputType=input_type)
    assert pwn_type["type"] == "Overflow"


def test_detect_64():
    with suppress():
        test_file = "tests/bin/bof_win_64"
        input_type = "STDIN"
        pwn_type = overflowDetector.checkOverflow(test_file, inputType=input_type)
    assert pwn_type["type"] == "Overflow"


def test_get_win_func():
    with suppress():
        test_file = "tests/bin/bof_win_32"
        win_functions = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in win_functions


def test_pwn_win_func_32():
    test_file = "tests/bin/bof_win_32"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    with suppress():
        properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in properties["win_functions"]

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"


def test_pwn_win_func_64():
    test_file = "tests/bin/bof_win_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    with suppress():
        properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in properties["win_functions"]

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"


def test_pwn_win_sc_32():
    # Setup for test
    test_file = "tests/bin/bof_32"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["file"] = test_file
    properties["force_shellcode"] = True

    # No win function allowed
    properties["win_functions"] = None
    with suppress():
        # Protections trigger exploit find type
        properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["nx"] == False

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"


def test_pwn_win_sc_64():
    # Setup for test
    test_file = "tests/bin/bof_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["file"] = test_file
    properties["force_shellcode"] = True

    # No win function allowed
    properties["win_functions"] = None

    with suppress():
        # Protections trigger exploit find type
        properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["nx"] == False

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"


def test_send_exploit():
    test_file = "tests/bin/bof_win_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}

    with suppress():
        properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in properties["win_functions"]

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"

    with suppress():
        properties["send_results"] = overflowExploitSender.sendExploit(
            test_file, properties
        )
    assert properties["send_results"]["flag_found"] == True


def test_leak_rop_32():

    test_file = "tests/bin/bof_nx_32"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["file"] = test_file

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "leak"


def test_leak_rop_64():

    test_file = "tests/bin/bof_nx_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["file"] = test_file

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "leak"


def test_pwn_rop_32():

    test_file = "tests/bin/bof_nx_32"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["input_type"] = input_type
    properties["file"] = test_file
    attempts = 3
    while attempts > 0:
        with suppress():
            # Protections trigger exploit find type
            properties["protections"] = protectionDetector.getProperties(test_file)

        with suppress():
            properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
                test_file, properties, inputType=input_type
            )
        assert properties["pwn_type"]["results"]["type"] == "leak"

        properties["send_results"] = overflowExploitSender.sendExploit(
            test_file, properties
        )

        if not properties["send_results"]["flag_found"]:
            attempts -= 1
            continue

        assert properties["send_results"]["flag_found"] == True
        break


def test_pwn_rop_64():

    test_file = "tests/bin/bof_nx_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["input_type"] = input_type
    properties["file"] = test_file
    attempts = 3
    while attempts > 0:
        with suppress():
            # Protections trigger exploit find type
            properties["protections"] = protectionDetector.getProperties(test_file)

        with suppress():
            properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
                test_file, properties, inputType=input_type
            )
        assert properties["pwn_type"]["results"]["type"] == "leak"

        properties["send_results"] = overflowExploitSender.sendExploit(
            test_file, properties
        )

        if not properties["send_results"]["flag_found"]:
            attempts -= 1
            continue

        assert properties["send_results"]["flag_found"] == True
        break


@pytest.mark.skip(reason="Not yet finished")
def test_pwn_libc_rop_32():

    test_file = "tests/bin/bof_nx_32"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["input_type"] = input_type
    properties["file"] = test_file
    properties["libc"] = "tests/bin/libc.so.6_i386"
    attempts = 3
    while attempts > 0:
        with suppress():
            # Protections trigger exploit find type
            properties["protections"] = protectionDetector.getProperties(test_file)

        with suppress():
            properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
                test_file, properties, inputType=input_type
            )
        assert properties["pwn_type"]["results"]["type"] == "leak"

        properties["send_results"] = overflowExploitSender.sendExploit(
            test_file, properties
        )

        if not properties["send_results"]["flag_found"]:
            attempts -= 1
            continue

        assert properties["send_results"]["flag_found"] == True
        break


def test_pwn_libc_rop_64():

    test_file = "tests/bin/bof_nx_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["input_type"] = input_type
    properties["file"] = test_file
    properties["libc"] = "tests/bin/libc.so.6_amd64"
    attempts = 3
    while attempts > 0:
        with suppress():
            # Protections trigger exploit find type
            properties["protections"] = protectionDetector.getProperties(test_file)

        with suppress():
            properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
                test_file, properties, inputType=input_type
            )
        assert properties["pwn_type"]["results"]["type"] == "leak"

        properties["send_results"] = overflowExploitSender.sendExploit(
            test_file, properties
        )

        if not properties["send_results"]["flag_found"]:
            attempts -= 1
            continue

        assert properties["send_results"]["flag_found"] == True
        break


def test_remote_libc_leak_64():
    """
    We'll host the binary and then do a ret2libc using
    only remote leaks
    """
    test_file = "tests/bin/bof_nx_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["input_type"] = input_type
    properties["file"] = test_file

    properties["remote"] = {}
    properties["remote"]["url"] = "localhost"
    properties["remote"]["port"] = random.randint(2048, 3096)

    if which("socat") is None:
        pytest.skip("Socat not installed. Skipping remote test")

    socat_path = which("socat")
    socat_cmd = "{} TCP4-LISTEN:{},tcpwrap=script,reuseaddr,fork EXEC:{}"
    socat_cmd = socat_cmd.format(
        socat_path, properties["remote"]["port"], os.path.abspath(test_file)
    )
    socat_cmd = shlex.split(socat_cmd)

    # Run binary with socat
    p = multiprocessing.Process(target=subprocess.check_call, args=(socat_cmd,))
    p.start()

    with suppress():
        # Protections trigger exploit find type
        properties["protections"] = protectionDetector.getProperties(test_file)

    properties["libc"] = overflowRemoteLeaker.leak_remote_functions(
        test_file, properties, inputType=properties["input_type"]
    )

    assert properties["libc"] is not None

    properties["pwn_type"]["results"] = {}
    properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
        test_file, properties, inputType=properties["input_type"]
    )
    assert properties["pwn_type"]["results"]["type"] is not None

    properties["remote_results"] = overflowExploitSender.sendExploit(
        test_file,
        properties,
        remote_server=True,
        remote_url=properties["remote"]["url"],
        port_num=properties["remote"]["port"],
    )

    assert properties["remote_results"] is not None

    p.kill()


"""
zerapwn.py /home/chris/projects/Zeratool/tests/bin/bof_dlresolve_64 \
    --force_dlresolve --skip_check --overflow_only --no_win
"""


def test_pwn_dlresolve_64():
    test_file = "tests/bin/bof_dlresolve_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}
    properties["input_type"] = input_type
    properties["file"] = test_file

    properties["force_dlresolve"] = True
    properties["win_functions"] = []
    properties["pwn_type"]["type"] = "Overflow"
    with suppress():
        # Protections trigger exploit find type
        properties["protections"] = protectionDetector.getProperties(test_file)

    with suppress():
        properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
            test_file, properties, inputType=input_type
        )
    assert properties["pwn_type"]["results"]["type"] == "dlresolve"

    properties["send_results"] = overflowExploitSender.sendExploit(
        test_file, properties
    )

    assert properties["send_results"]["flag_found"] == True
