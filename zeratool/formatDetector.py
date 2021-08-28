import angr
from angr import sim_options as so
import claripy
import time
import timeout_decorator
import tqdm
from zeratool import printf_model
import logging

log = logging.getLogger(__name__)


def checkFormat(binary_name, inputType="STDIN"):

    p = angr.Project(binary_name, load_options={"auto_load_libs": False})

    # Stdio based ones
    p.hook_symbol("printf", printf_model.printFormat(0))
    p.hook_symbol("fprintf", printf_model.printFormat(1))
    p.hook_symbol("dprintf", printf_model.printFormat(1))
    p.hook_symbol("sprintf", printf_model.printFormat(1))
    p.hook_symbol("snprintf", printf_model.printFormat(2))

    # Stdarg base ones
    p.hook_symbol("vprintf", printf_model.printFormat(0))
    p.hook_symbol("vfprintf", printf_model.printFormat(1))
    p.hook_symbol("vdprintf", printf_model.printFormat(1))
    p.hook_symbol("vsprintf", printf_model.printFormat(1))
    p.hook_symbol("vsnprintf", printf_model.printFormat(2))

    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY, so.TRACK_CONSTRAINTS}
    # Setup state based on input type
    argv = [binary_name]
    input_arg = claripy.BVS("input", 300 * 8)
    if inputType == "STDIN":
        state = p.factory.full_init_state(
            args=argv,
            stdin=input_arg,
            add_options=extras,
        )
        state.globals["user_input"] = input_arg
    elif inputType == "LIBPWNABLE":
        handle_connection = p.loader.main_object.get_symbol("handle_connection")
        state = p.factory.entry_state(
            addr=handle_connection.rebased_addr,
            add_options=extras,
        )
        state.globals["user_input"] = input_arg
    else:
        argv.append(input_arg)
        state = p.factory.full_init_state(
            args=argv,
            add_options=extras,
        )
        state.globals["user_input"] = input_arg

    state.libc.buf_symbolic_bytes = 0x100
    state.globals["inputType"] = inputType
    simgr = p.factory.simgr(state, save_unconstrained=True)

    run_environ = {}
    run_environ["type"] = None
    end_state = None
    # Lame way to do a timeout
    try:

        @timeout_decorator.timeout(1200)
        def exploreBinary(simgr):
            simgr.explore(find=lambda s: "type" in s.globals)

        exploreBinary(simgr)
        if "found" in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ["type"] = end_state.globals["type"]
            run_environ["position"] = end_state.globals["position"]
            run_environ["length"] = end_state.globals["length"]

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        print("[~] Format check timed out")

    if "input" in end_state.globals.keys():
        run_environ["input"] = end_state.globals["input"]
        print("[+] Triggerable with input : {}".format(end_state.globals["input"]))

    return run_environ
