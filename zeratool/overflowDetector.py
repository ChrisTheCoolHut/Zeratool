import angr
from angr import sim_options as so
import claripy
import time
import timeout_decorator
import IPython
from .simgr_helper import overflow_detect_filter, hook_win, hook_four
import logging

log = logging.getLogger(__name__)


def checkOverflow(binary_name, inputType="STDIN"):

    extras = {
        so.REVERSE_MEMORY_NAME_MAP,
        so.TRACK_ACTION_HISTORY,
        so.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        so.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})
    # Hook rands
    p.hook_symbol("rand", hook_four())
    p.hook_symbol("srand", hook_four())

    p.hook_symbol("system", hook_win())
    # p.hook_symbol('fgets',angr.SIM_PROCEDURES['libc']['gets']())

    # Setup state based on input type
    argv = [binary_name]
    input_arg = claripy.BVS("input", 300 * 8)
    if inputType == "STDIN":
        state = p.factory.full_init_state(args=argv, stdin=input_arg)
        state.globals["user_input"] = input_arg
    elif inputType == "LIBPWNABLE":
        handle_connection = p.loader.main_object.get_symbol("handle_connection")
        state = p.factory.entry_state(
            addr=handle_connection.rebased_addr, stdin=input_arg, add_options=extras
        )
        state.globals["user_input"] = input_arg
    else:
        argv.append(input_arg)
        state = p.factory.full_init_state(args=argv)
        state.globals["user_input"] = input_arg

    state.libc.buf_symbolic_bytes = 0x100
    state.globals["inputType"] = inputType
    simgr = p.factory.simgr(state, save_unconstrained=True)

    run_environ = {}
    run_environ["type"] = None
    end_state = None
    # Lame way to do a timeout
    try:

        @timeout_decorator.timeout(120)
        def exploreBinary(simgr):
            simgr.explore(
                find=lambda s: "type" in s.globals, step_func=overflow_detect_filter
            )

        exploreBinary(simgr)
        if "found" in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ["type"] = end_state.globals["type"]

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    if "input" in run_environ.keys() or run_environ["type"] == "overflow_variable":
        run_environ["input"] = end_state.globals["input"]
        log.info("[+] Triggerable with input : {}".format(end_state.globals["input"]))
    return run_environ
