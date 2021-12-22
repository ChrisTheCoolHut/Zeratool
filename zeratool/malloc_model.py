import angr


class malloc_addr_tracker(angr.procedures.libc.malloc.malloc):
    IS_FUNCTION = True

    def store_addr(self, addr):

        if "stored_malloc" not in self.state.globals.keys():
            self.state.globals["stored_malloc"] = []
        self.state.globals["stored_malloc"].append(addr)

    def run(self, sim_size):
        addr = super(type(self), self).run(sim_size)
        self.store_addr(addr)
        return addr
