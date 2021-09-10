from pwn import *
import angr
import claripy
import tqdm


class putsFormat(angr.procedures.libc.puts.puts):
    IS_FUNCTION = True

    def check_for_leak(self, string):

        state = self.state

        if state.globals["needs_leak"]:

            # string should be a ptr, we are going to check
            # to see if it's pointing to a got entry
            elf = ELF(state.project.filename)
            string_addr = state.solver.eval(string)

            for name,addr in elf.got.items():
                if string_addr == addr:
                    print("[+] Puts leaked {}".format(name))
                    state.globals["leaked_func"] = name
                    return True

        return False

    def run(self, string):
        if not self.check_for_leak(string):
            return super(type(self), self).run(string)