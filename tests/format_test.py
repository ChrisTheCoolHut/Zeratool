import os
import pytest

os.environ["PWNLIB_NOTERM"] = "1"
from zeratool import winFunctionDetector
from zeratool import protectionDetector
from zeratool import formatDetector
from zeratool import formatLeak
from zeratool import formatExploiter


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
        test_file = "tests/bin/read_stack_32"
        input_type = "STDIN"
        pwn_type = formatDetector.checkFormat(test_file, inputType=input_type)
    assert pwn_type["type"] == "Format"


def test_detect_64():
    with suppress():
        test_file = "tests/bin/read_stack_64"
        input_type = "STDIN"
        pwn_type = formatDetector.checkFormat(test_file, inputType=input_type)
    assert pwn_type["type"] == "Format"


def test_leak_32():
    with suppress():
        test_file = "tests/bin/read_stack_32"
        properties = {"pwn_type": {}, "pwn": {}, "input_type": "STDIN"}

        properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    with suppress():
        properties["pwn_type"] = formatDetector.checkFormat(
            test_file, inputType=properties["input_type"]
        )

    assert properties["pwn_type"]["type"] == "Format"
    with suppress():
        properties["pwn"] = formatLeak.checkLeak(test_file, properties)
    assert properties["pwn"]["flag_found"] == True


def test_leak_64():
    test_file = "tests/bin/read_stack_64"
    properties = {"pwn_type": {}, "pwn": {}, "input_type": "STDIN"}

    with suppress():
        properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    with suppress():
        properties["pwn_type"] = formatDetector.checkFormat(
            test_file, inputType=properties["input_type"]
        )

    assert properties["pwn_type"]["type"] == "Format"
    with suppress():
        properties["pwn"] = formatLeak.checkLeak(test_file, properties)
    assert properties["pwn"]["flag_found"] == True


def test_win_32():
    test_file = "tests/bin/format_pc_write_32"
    properties = {"pwn_type": {}, "pwn": {}, "input_type": "STDIN"}

    with suppress():
        properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    with suppress():
        properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
        print(properties["win_functions"])
    assert "sym.secret_function" in properties["win_functions"]

    with suppress():
        properties["pwn_type"] = formatDetector.checkFormat(
            test_file, inputType=properties["input_type"]
        )
    assert properties["pwn_type"]["type"] == "Format"

    with suppress():
        properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
            test_file, properties
        )

    assert "flag_found" in properties["pwn_type"]["results"].keys()


def test_win_64():
    import logging

    logging.basicConfig()
    logging.root.setLevel(logging.INFO)
    test_file = "tests/bin/format_pc_write_64"
    properties = {"pwn_type": {}, "pwn": {}, "input_type": "STDIN"}

    with suppress():
        properties["pwn_type"] = formatDetector.checkFormat(
            test_file, inputType=properties["input_type"]
        )
    assert properties["pwn_type"]["type"] == "Format"

    with suppress():
        properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    with suppress():
        properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.secret_function" in properties["win_functions"]

    with suppress():
        properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
            test_file, properties
        )

    assert "flag_found" in properties["pwn_type"]["results"].keys()
