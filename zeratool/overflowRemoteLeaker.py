import angr
import claripy
import timeout_decorator
import os
from struct import pack
from angr import sim_options as so
from zeratool import puts_model
import logging

log = logging.getLogger(__name__)

# from pwn import *

from .simgr_helper import (
    point_to_win_filter,
    point_to_shellcode_filter,
    point_to_ropchain_filter,
    leak_remote_libc_functions,
    hook_four,
)
from .radare_helper import getRegValues, findShellcode, get_base_addr


def leak_remote_functions(binary_name, properties, inputType="STDIN"):

    run_environ = properties["pwn_type"].get("results", {})
    run_environ["type"] = run_environ.get("type", None)

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})

    # Don't even try for pic
    if p.loader.main_object.pic:
        return

    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY, so.TRACK_CONSTRAINTS}

    p.hook_symbol("rand", hook_four())
    p.hook_symbol("srand", hook_four())
    p.hook_symbol("puts", puts_model.putsFormat())

    # Setup state based on input type
    argv = [binary_name]
    input_arg = claripy.BVS("input", 400 * 8)
    if inputType == "STDIN":
        entry_addr = p.loader.main_object.entry
        reg_values = getRegValues(binary_name, entry_addr)

        state = p.factory.full_init_state(
            args=argv,
            add_options=extras,
            stdin=input_arg,
            env=os.environ,
        )

        # Just set the registers
        register_names = list(state.arch.register_names.values())
        for register in register_names:
            if register in reg_values:  # Didn't use the register
                state.registers.store(register, reg_values[register])

    elif inputType == "LIBPWNABLE":

        handle_connection = p.loader.main_object.get_symbol("handle_connection")
        start_addr = handle_connection.rebased_addr

        reg_values = getRegValues(binary_name, start_addr)

        state = p.factory.entry_state(
            args=argv,
            env=os.environ,
            addr=start_addr,
            add_options=extras,
            stdin=input_arg,
        )

        # Just set the registers
        register_names = list(state.arch.register_names.values())
        for register in register_names:
            if register in reg_values:  # Didn't use the register
                state.registers.store(register, reg_values[register])

    state.libc.buf_symbolic_bytes = 0x200
    state.globals["user_input"] = input_arg
    state.globals["inputType"] = inputType
    state.globals["properties"] = properties
    state.globals["needs_leak"] = True
    simgr = p.factory.simgr(state, save_unconstrained=True)

    end_state = None
    # Lame way to do a timeout
    try:

        @timeout_decorator.timeout(1200)
        def exploreBinary(simgr):
            simgr.explore(
                find=lambda s: "libc" in s.globals, step_func=leak_remote_libc_functions
            )

        exploreBinary(simgr)

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Overflow check timed out")
        return run_environ

    end_state = simgr.found[0]

    if end_state.globals.get("libc", False):
        log.info("Found remote libc")
        run_environ["remote_libc"] = end_state.globals["libc"]
        log.info(run_environ["remote_libc"])

    return run_environ
