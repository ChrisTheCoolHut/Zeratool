from pwn import *
import angr
import claripy
import tqdm

# Better symbolic strlen
def get_max_strlen(state, value):
    i = 0
    for c in value.chop(8): # Chop by byte
        i += 1
        if not state.solver.satisfiable([c != 0x00]):
            print("Found the null at offset : {}".format(i))
            return i-1
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

    def __init__(self,input_index):
        # Set user input index for different
        # printf types
        self.input_index=input_index
        angr.procedures.libc.printf.printf.__init__(self)

    def checkExploitable(self):

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

        printf_arg = self.arg(i)

        # Sanity check
        if self.state.solver.symbolic(printf_arg):
            print("printf arg ptr is symbolic! HOW?".format(i))

        var_loc = solv(printf_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(var_loc, max_read_len)
        var_len = get_max_strlen(state, var_data)

        # Reload with just our max len
        var_data = state.memory.load(var_loc, var_len)

        print("Building list of symbolic bytes")
        symbolic_list = [
            state.memory.load(var_loc + x,1).symbolic
            for x in range(var_len)
        ]
        print("Done Building list of symbolic bytes")

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
        print(
            "[+] Found symbolic buffer at position {} of length {}".format(
                position, greatest_count
            )
        )

        if greatest_count > 0:
            str_val = b"%lx_"
            if bits == 64:
                str_val = b"%llx_"
            if self.can_constrain_bytes(state,var_data,var_loc, position,var_len,strVal=str_val):
                print("[+] Can constrain bytes")
                print("[+] Constraining input to leak")

                self.constrainBytes(
                    state,
                    var_data,
                    var_loc,
                    position,
                    var_len,
                    strVal=str_val,
                )
                # Verify solution
                #stdin_str = str(state_copy.posix.dumps(0))
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
        for i in tqdm.tqdm(range(length),total=length, desc="Checking Constraints"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i,1)
            if not state.solver.satisfiable(extra_constraints=[curr_byte == strVal[strValIndex]]):
                return False
        return True

    def constrainBytes(self, state, symVar, loc, position, length, strVal=b"%x_"):
        for i in tqdm.tqdm(range(length),total=length, desc="Constraining"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i,1)
            if state.solver.satisfiable(extra_constraints=[curr_byte == strVal[strValIndex]]):
                state.add_constraints(curr_byte == strVal[strValIndex])
            else:
                print(
                    "[~] Byte {} not constrained to {}".format(i, strVal[strValIndex])
                )

    def run(self):
        if not self.checkExploitable():
            return super(type(self), self).run()