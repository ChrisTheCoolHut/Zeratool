from __future__ import print_function
import angr
import claripy
import time
import timeout_decorator
import IPython

def checkOverflow(binary_name,inputType="STDIN"):

    class hookFour(angr.SimProcedure):
        IS_FUNCTION = True
        def run(self):
            return 4 # Fair dice roll

    p = angr.Project(binary_name,load_options={"auto_load_libs": False})
    #Hook rands
    p.hook_symbol('rand',hookFour)
    p.hook_symbol('srand',hookFour)

    #Setup state based on input type
    argv = [binary_name]
    if inputType == "STDIN":
        state = p.factory.full_init_state(args=argv)
    elif inputType == "LIBPWNABLE":
        handle_connection = p.loader.main_object.get_symbol('handle_connection')
        state = p.factory.entry_state(addr=handle_connection.rebased_addr)
    else:
        arg = claripy.BVS("arg1", 300 * 8)
        argv.append(arg)
        state = p.factory.full_init_state(args=argv)
        state.globals['arg'] = arg

    state.globals['inputType'] = inputType
    simgr = p.factory.simgr(state, immutable=False, save_unconstrained=True)

    def overflow_filter(simgr):

        for path in simgr.unconstrained:
            state = path.state

            eip = state.regs.pc
            bits = state.arch.bits
            state_copy = state.copy()

            #Constrain pc to 0x41414141 or 0x41414141414141
            constraints = []
            for i in range(bits / 8):
                curr_byte = eip.get_byte(i)
                constraint = claripy.And(curr_byte == 0x41)
                constraints.append(constraint)

            #Check satisfiability
            if state_copy.se.satisfiable(extra_constraints=constraints):
                for constraint in constraints:
                    state_copy.add_constraints(constraint)

                #Check by input
                if state_copy.globals['inputType'] == "STDIN" or state_copy.globals['inputType'] == "LIBPWNABLE":
                    stdin_str = str(state_copy.posix.dumps(0).replace('\x00','').replace('\x01',''))
                    if 'A' in stdin_str:

                        #Constrain EIP to 0x41414141 or 0x4141414141414141
                        constraints = []
                        for i in range(bits / 8):
                            curr_byte = eip.get_byte(i)
                            constraint = claripy.And(curr_byte == 0x41)
                            constraints.append(constraint)

                        #Constrain STDIN to printable if we can
                        if state.se.satisfiable(extra_constraints=constraints):
                            for constraint in constraints:
                                state.add_constraints(constraint)


                        #Constrain rest of input to be printable
                        stdin = state.posix.files[0]
                        constraints = []
                        #stdin_size = len(stdin.all_bytes())
                        stdin_size = 300
                        stdin.length = stdin_size
                        stdin.seek(0)
                        stdin_bytes = stdin.all_bytes()
                        for i in range(stdin_size):
                            curr_byte = stdin.read_from(1)
                            constraint = claripy.And(curr_byte > 0x2F, curr_byte < 0x7F)
                            if state.se.satisfiable(extra_constraints=[constraint]):
                                constraints.append(constraint)
    
                        #Constrain STDIN to printable if we can
                        if state.se.satisfiable(extra_constraints=constraints):
                            for constraint in constraints:
                                state.add_constraints(constraint)

                        #Get the string coming into STDIN
                        stdin_str = repr(str(state.posix.dumps(0).replace('\x00','').replace('\x01','')))
                        print("[+] Vulnerable path found {}".format(stdin_str))
                        state.globals['type'] = "Overflow"
                        simgr.stashes['found'].append(path)
                        simgr.stashes['unconstrained'].remove(path)


                if state_copy.globals['inputType'] == "ARG":
                    arg = state.globals['arg']
                    arg_str = str(state_copy.solver.eval(arg,cast_to=str)).replace('\x00','').replace('\x01','')
                    if 'A' in arg_str:
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
    
                        #Constrain STDIN to printable if we can
                        if state.se.satisfiable(extra_constraints=constraints):
                            for constraint in constraints:
                                state.add_constraints(constraint)
                        

                        arg_str = repr(str(state.solver.eval(arg,cast_to=str)).replace('\x00','').replace('\x01',''))
                        print("[+] Vulnerable path found {}".format(arg_str))
                        state.globals['type'] = "Overflow"
                        simgr.stashes['found'].append(path)
                        simgr.stashes['unconstrained'].remove(path)
        return simgr

    run_environ = {}
    run_environ['type'] = None
    end_state = None
    #Lame way to do a timeout
    try:
        @timeout_decorator.timeout(120)
        def exploreBinary(simgr):
            simgr.explore(find=lambda s: 'type' in s.globals,step_func=overflow_filter)

        exploreBinary(simgr)
        if 'found' in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ['type'] = end_state.globals['type']


    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        print("[~] Keyboard Interrupt")
    if (inputType == "STDIN" or inputType == "LIBPWNABLE")and end_state is not None:
        stdin_str = repr(str(end_state.posix.dumps(0).replace('\x00','').replace('\x01','')))
        run_environ['input'] = stdin_str
        print("[+] Triggerable with STDIN : {}".format(stdin_str))
    elif inputType == "ARG" and end_state is not None:
        arg_str = repr(str(end_state.solver.eval(arg,cast_to=str)).replace('\x00','').replace('\x01',''))
        run_environ['input'] = arg_str
        print("[+] Triggerable with arg : {}".format(arg_str))

    return run_environ
