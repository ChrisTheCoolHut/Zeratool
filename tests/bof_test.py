import os
import pytest

os.environ["PWNLIB_NOTERM"] = "1"
from zeratool import overflowDetector
from zeratool import overflowExploiter
from zeratool import overflowExploitSender
from zeratool import winFunctionDetector
from zeratool import protectionDetector

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
