import os
import pytest

os.environ["PWNLIB_NOTERM"] = "1"
from zeratool import winFunctionDetector
from zeratool import protectionDetector
from zeratool import formatDetector
from zeratool import formatLeak
from zeratool import formatExploiter

def test_detect_32():
    test_file = "tests/bin/read_stack_32"
    input_type = "STDIN"
    pwn_type = formatDetector.checkFormat(test_file, inputType=input_type)
    assert pwn_type["type"] == "Format"


def test_detect_64():
    test_file = "tests/bin/read_stack_64"
    input_type = "STDIN"
    pwn_type = formatDetector.checkFormat(test_file, inputType=input_type)
    assert pwn_type["type"] == "Format"


def test_leak_32():
    test_file = "tests/bin/read_stack_32"
    properties = {"pwn_type" : {}, "pwn" : {}, "input_type" : "STDIN"}

    properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    properties["pwn_type"] = formatDetector.checkFormat(test_file, inputType=properties["input_type"])

    assert properties["pwn_type"]["type"] == "Format"
    properties["pwn"] = formatLeak.checkLeak(test_file, properties)
    assert properties["pwn"]["flag_found"] == True


def test_leak_64():
    test_file = "tests/bin/read_stack_64"
    properties = {"pwn_type" : {}, "pwn" : {}, "input_type" : "STDIN"}

    properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    properties["pwn_type"] = formatDetector.checkFormat(test_file, inputType=properties["input_type"])

    assert properties["pwn_type"]["type"] == "Format"
    properties["pwn"] = formatLeak.checkLeak(test_file, properties)
    assert properties["pwn"]["flag_found"] == True


def test_win_32():
    test_file = "tests/bin/format_pc_write_32"
    properties = {"pwn_type" : {}, "pwn" : {}, "input_type" : "STDIN"}

    properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    print(properties["win_functions"])
    assert "sym.secret_function" in properties["win_functions"]

    properties["pwn_type"] = formatDetector.checkFormat(test_file, inputType=properties["input_type"])
    assert properties["pwn_type"]["type"] == "Format"

    properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
        test_file, properties
    )

    assert "flag_found" in properties["pwn_type"]["results"].keys()

@pytest.mark.skip(reason="fgets is clobbering null byte")
def test_win_64():
    test_file = "tests/bin/format_pc_write_64"
    properties = {"pwn_type" : {}, "pwn" : {}, "input_type" : "STDIN"}

    properties["protections"] = protectionDetector.getProperties(test_file)
    assert properties["protections"]["arch"]

    properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.secret_function" in properties["win_functions"]

    properties["pwn_type"] = formatDetector.checkFormat(test_file, inputType=properties["input_type"])
    assert properties["pwn_type"]["type"] == "Format"

    properties["pwn_type"]["results"] = formatExploiter.exploitFormat(
        test_file, properties
    )

    assert "flag_found" in properties["pwn_type"].keys()