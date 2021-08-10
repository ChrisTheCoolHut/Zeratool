import os

os.environ["PWNLIB_NOTERM"] = "1"
from zeratool import overflowDetector
from zeratool import overflowExploiter
from zeratool import overflowExploitSender
from zeratool import winFunctionDetector


def test_detect_32():
    test_file = "tests/bof_win_32"
    input_type = "STDIN"
    pwn_type = overflowDetector.checkOverflow(test_file, inputType=input_type)
    assert pwn_type["type"] == "Overflow"


def test_detect_64():
    test_file = "tests/bof_win_64"
    input_type = "STDIN"
    pwn_type = overflowDetector.checkOverflow(test_file, inputType=input_type)
    assert pwn_type["type"] == "Overflow"


def test_get_win_func():
    test_file = "tests/bof_win_32"
    win_functions = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in win_functions


def test_pwn_win_func_32():
    test_file = "tests/bof_win_32"
    input_type = "STDIN"
    properties = {"pwn_type": {}}

    properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in properties["win_functions"]

    properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
        test_file, properties, inputType=input_type
    )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"


def test_pwn_win_func_64():
    test_file = "tests/bof_win_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}

    properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in properties["win_functions"]

    properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
        test_file, properties, inputType=input_type
    )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"


def test_send_exploit():
    test_file = "tests/bof_win_64"
    input_type = "STDIN"
    properties = {"pwn_type": {}}

    properties["win_functions"] = winFunctionDetector.getWinFunctions(test_file)
    assert "sym.print_flag" in properties["win_functions"]

    properties["pwn_type"]["results"] = overflowExploiter.exploitOverflow(
        test_file, properties, inputType=input_type
    )
    assert properties["pwn_type"]["results"]["type"] == "Overflow"

    properties["send_results"] = overflowExploitSender.sendExploit(
        test_file, properties
    )
    assert properties["send_results"]["flag_found"] == True
