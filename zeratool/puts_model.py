from pwn import *
import angr
import claripy
import tqdm
import logging

log = logging.getLogger(__name__)


class putsFormat(angr.procedures.libc.puts.puts):
    IS_FUNCTION = True

    def check_for_leak(self, string):

        state = self.state

        if state.globals["needs_leak"] or True:
            # string should be a ptr, we are going to check
            # to see if it's pointing to a got entry
            elf = ELF(state.project.filename)
            string_addr = state.solver.eval(string)
            for name, addr in elf.got.items():
                if string_addr == addr:
                    log.info("[+] Puts leaked {}".format(name))
                    state.globals["output_before_leak"] = state.posix.dumps(1)
                    state.globals["leaked_func"] = name
                    # return True

        return False

    def run(self, string):
        self.check_for_leak(string)

        # Wait till angr #3026 gets merged, then change it back
        # to
        # return super(type(self), self).run(string)

        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        length = self.inline_call(strlen, string).ret_expr
        out = stdout.write(string, length)
        stdout.write_data(self.state.solver.BVV(b"\n"))
        return out + 1
