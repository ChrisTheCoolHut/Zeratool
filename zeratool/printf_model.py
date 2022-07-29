from pwn import *
import angr
import claripy
import tqdm
from .simgr_helper import get_trimmed_input
import logging
import copy

log = logging.getLogger(__name__)

# Better symbolic strlen
def get_max_strlen(state, value):
    i = 0
    for c in value.chop(8):  # Chop by byte
        i += 1
        if not state.solver.satisfiable([c != 0x00]):
            log.debug("Found the null at offset : {}".format(i))
            return i - 1
    return i


"""
Model either printf("User input") or printf("%s","Userinput")
"""


class printFormat(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    input_index = 0
    """
    Checks userinput arg
    """

    def __init__(self, input_index):
        # Set user input index for different
        # printf types
        self.input_index = input_index
        angr.procedures.libc.printf.printf.__init__(self)

    def checkExploitable(self, fmt):

        bits = self.state.arch.bits
        load_len = int(bits / 8)
        max_read_len = 1024
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        i = self.input_index
        state = self.state
        solv = state.solver.eval

        # fmt_len = self._sim_strlen(fmt)
        # # We control format specifier and strlen isn't going to be helpful,
        # # just set it ourselves
        # if len(state.solver.eval_upto(fmt_len,2)) > 1:
        #     while not state.satisfiable(extra_constraints=[fmt_len == max_read_len]):
        #         max_read_len -=1
        #         if max_read_len < 0:
        #             raise Exception("fmt string with no length!")
        #     state.add_constraints(fmt_len == max_read_len)

        if len(self.arguments) <= i:
            return False
        printf_arg = self.arguments[i]

        var_loc = solv(printf_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(var_loc, max_read_len)
        var_len = get_max_strlen(state, var_data)

        fmt_len = self._sim_strlen(fmt)
        # if len(state.solver.eval_upto(fmt_len,2)) > 1:
        #     state.add_constraints(fmt_len == var_len)

        # Reload with just our max len
        var_data = state.memory.load(var_loc, var_len)

        log.info("Building list of symbolic bytes")
        symbolic_list = [
            state.memory.load(var_loc + x, 1).symbolic for x in range(var_len)
        ]
        log.info("Done Building list of symbolic bytes")

        """
        Iterate over the characters in the string
        Checking for where our symbolic values are
        This helps in weird cases like:

        char myVal[100] = "I\'m cool ";
        strcat(myVal,STDIN);
        printf(myVal);
        """
        position = 0
        count = 0
        greatest_count = 0
        prev_item = symbolic_list[0]
        for i in range(1, len(symbolic_list)):
            if symbolic_list[i] and symbolic_list[i] == symbolic_list[i - 1]:
                count = count + 1
                if count > greatest_count:
                    greatest_count = count
                    position = i - count
            else:
                if count > greatest_count:
                    greatest_count = count
                    position = i - 1 - count
                    # previous position minus greatest count
                count = 0
        log.info(
            "[+] Found symbolic buffer at position {} of length {}".format(
                position, greatest_count
            )
        )

        if greatest_count > 0:
            str_val = b"%lx_"
            if bits == 64:
                str_val = b"%llx_"
            if self.can_constrain_bytes(
                state, var_data, var_loc, position, var_len, strVal=str_val
            ):
                log.info("[+] Can constrain bytes")
                log.info("[+] Constraining input to leak")

                self.constrainBytes(
                    state,
                    var_data,
                    var_loc,
                    position,
                    var_len,
                    strVal=str_val,
                )
                # Verify solution
                # stdin_str = str(state_copy.posix.dumps(0))
                # user_input = self.state.globals["inputType"]
                # if str_val in solv(user_input):
                #     var_value = self.state.memory.load(var_loc)
                #     self.constrainBytes(
                #         self.state, var_value, var_loc, position, var_value_length
                #     )
                # print("[+] Vulnerable path found {}".format(vuln_string))
                user_input = state.globals["user_input"]

                self.state.globals["input"] = solv(user_input, cast_to=bytes)
                self.state.globals["type"] = "Format"
                self.state.globals["position"] = position
                self.state.globals["length"] = greatest_count

                return True

        return False

    def can_constrain_bytes(self, state, symVar, loc, position, length, strVal=b"%x_"):
        total_region = self.state.memory.load(loc, length)
        total_format = strVal * length
        # If we can constrain it all in one go, then let's do it!
        if state.solver.satisfiable(
            extra_constraints=[total_region == total_format[:length]]
        ):
            log.info("Can constrain it all, let's go!")
            state.add_constraints(total_region == total_format[:length])
            return True

        for i in tqdm.tqdm(range(length), total=length, desc="Checking Constraints"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i, 1)
            if not state.solver.satisfiable(
                extra_constraints=[curr_byte == strVal[strValIndex]]
            ):
                return False
        return True

    def constrainBytes(self, state, symVar, loc, position, length, strVal=b"%x_"):

        total_region = self.state.memory.load(loc, length)
        total_format = strVal * length
        # If we can constrain it all in one go, then let's do it!
        if state.solver.satisfiable(
            extra_constraints=[total_region == total_format[:length]]
        ):
            log.info("Can constrain it all, let's go!")
            state.add_constraints(total_region == total_format[:length])
            return

        for i in tqdm.tqdm(range(length), total=length, desc="Constraining"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i, 1)
            if state.solver.satisfiable(
                extra_constraints=[curr_byte == strVal[strValIndex]]
            ):
                state.add_constraints(curr_byte == strVal[strValIndex])
            else:
                log.info(
                    "[~] Byte {} not constrained to {}".format(i, strVal[strValIndex])
                )

    def run(self, _, fmt):
        if not self.checkExploitable(fmt):
            return super(type(self), self).run(fmt)


class printf_leak_detect(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    format_index = 0
    """
    Checks userinput arg
    """

    def __init__(self, format_index):
        # Set user input index for different
        # printf types
        self.format_index = format_index
        super(type(self), self).__init__()

    def check_for_leak(self, fmt):

        bits = self.state.arch.bits
        load_len = int(bits / 8)
        max_read_len = 1024
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        state = self.state
        p = self.state.project
        elf = ELF(state.project.filename)

        fmt_str = self._parse(fmt)

        for component in fmt_str.components:

            # We only want format specifiers
            if (
                isinstance(component, bytes)
                or isinstance(component, str)
                or isinstance(component, claripy.ast.BV)
            ):
                continue

            printf_arg = component

            fmt_spec = component

            i_val = self.va_arg("void*")

            c_val = int(state.solver.eval(i_val))
            c_val &= (1 << (fmt_spec.size * 8)) - 1
            if fmt_spec.signed and (c_val & (1 << ((fmt_spec.size * 8) - 1))):
                c_val -= 1 << fmt_spec.size * 8

            if fmt_spec.spec_type in (b"d", b"i"):
                s_val = str(c_val)
            elif fmt_spec.spec_type == b"u":
                s_val = str(c_val)
            elif fmt_spec.spec_type == b"c":
                s_val = chr(c_val & 0xFF)
            elif fmt_spec.spec_type == b"x":
                s_val = hex(c_val)[2:]
            elif fmt_spec.spec_type == b"o":
                s_val = oct(c_val)[2:]
            elif fmt_spec.spec_type == b"p":
                s_val = hex(c_val)
            else:
                log.warning("Unimplemented format specifier '%s'" % fmt_spec.spec_type)
                continue

            if isinstance(fmt_spec.length_spec, int):
                s_val = s_val.rjust(fmt_spec.length_spec, fmt_spec.pad_chr)

            var_addr = c_val

            # Are any pointers GOT addresses?
            for name, addr in elf.got.items():
                if var_addr == addr:
                    log.info("[+] Printf leaked GOT {}".format(name))
                    state.globals["leaked_type"] = "function"
                    state.globals["leaked_func"] = name
                    state.globals["leaked_addr"] = var_addr

                    # Input to leak
                    user_input = state.globals["user_input"]
                    input_bytes = state.solver.eval(user_input, cast_to=bytes)

                    state.globals["leak_input"] = input_bytes
                    state.globals["leak_output"] = state.posix.dumps(1)
                    return True
            # Heap and stack addrs should be in a heap or stack
            # segment, but angr doesn't map those segments so the
            # below call will not work
            # found_obj = p.loader.find_segment_containing(var_addr)

            # Check for stack address leak
            # So we have a dumb check to see if it's a stack addr
            stack_ptr = state.solver.eval(state.regs.sp)

            var_addr_mask = var_addr >> 28
            stack_ptr_mask = stack_ptr >> 28

            if var_addr_mask == stack_ptr_mask:
                log.info("[+] Leaked a stack addr : {}".format(hex(var_addr)))
                state.globals["leaked_type"] = "stack_address"
                state.globals["leaked_addr"] = var_addr

                # Input to leak
                user_input = state.globals["user_input"]
                input_bytes = state.solver.eval(user_input, cast_to=bytes)

                input_bytes = get_trimmed_input(user_input, state)

                state.globals["leak_input"] = input_bytes
                state.globals["leak_output"] = state.posix.dumps(1)
            # Check tracked malloc addrs
            if "stored_malloc" in self.state.globals.keys():
                for addr in self.state.globals["stored_malloc"]:
                    if addr == var_addr:
                        log.info("[+] Leaked a heap addr : {}".format(hex(var_addr)))
                        state.globals["leaked_type"] = "heap_address"
                        state.globals["leaked_addr"] = var_addr

                        # Input to leak
                        user_input = state.globals["user_input"]
                        input_bytes = state.solver.eval(user_input, cast_to=bytes)

                        state.globals["leak_input"] = input_bytes
                        state.globals["leak_output"] = state.posix.dumps(1)

    def run(self, fmt):
        """
        Iterating over the va_args checking for a leak
        will consume them and prevent us from printing
        normally, so we need to make a copy.
        """
        try:
            va_args_copy = copy.deepcopy(self)
        except:
            # Just bail out
            return super(type(self), self).run(fmt)

        va_args_copy.check_for_leak(fmt)

        return super(type(self), self).run(fmt)
