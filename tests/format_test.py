import os
import pytest

os.environ["PWNLIB_NOTERM"] = "1"
from zeratool import winFunctionDetector
from zeratool import protectionDetector
from zeratool import formatDetector
from zeratool import formatLeak

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