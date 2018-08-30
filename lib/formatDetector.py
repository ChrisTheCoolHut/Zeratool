from __future__ import print_function
import angr
import claripy
import time
import timeout_decorator
import IPython

try:
    xrange          # Python 2
except NameError:
    xrange = range  # Python 3


'''
Model either printf("User input") or printf("%s","Userinput")
'''
class printFormat(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    '''
    Checks up to two args
    '''
    def checkExploitable(self):


        '''
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        '''
        for i in xrange(5):
            state_copy = self.state.copy()
            
            solv = state_copy.solver.eval

            printf_arg = self.arg(i)

            var_loc = solv(printf_arg)

            var_value = state_copy.memory.load(var_loc)

            var_value_length = int("0x"+str(var_value.length),16)

            symbolic_list = [state_copy.memory.load(var_loc + x).get_byte(0).symbolic for x in xrange(var_value_length)]


            '''
            Iterate over the characters in the string
            Checking for where our symbolic values are
            This helps in weird cases like:

            char myVal[100] = "I\'m cool ";
            strcat(myVal,STDIN);
            printf("My super cool string is %s",myVal);
            '''
            position = 0
            count = 0
            greatest_count = 0
            prev_item = symbolic_list[0]
            for i in range(1,len(symbolic_list)):
                    if symbolic_list[i] and symbolic_list[i] == symbolic_list[i-1]:
                        count = count +1
                        if (count > greatest_count):
                            greatest_count = count
                            position = i - count
                    else:
                        if (count > greatest_count):
                            greatest_count = count
                            position = i - 1 - count
                            #previous position minus greatest count
                        count = 0
            print("[+] Found symbolic buffer at position {} of length {}".format(position,greatest_count))

            if greatest_count > 0:
                str_val = "%x_"
                self.constrainBytes(state_copy,var_value,var_loc,position,var_value_length,strVal=str_val)
                vuln_string = solv(var_value, cast_to=str)

                #Verify solution
                if state_copy.globals['inputType'] == "STDIN" or state_copy.globals['inputType'] == "LIBPWNABLE":
                    stdin_str = str(state_copy.posix.dumps(0))
                    if str_val in stdin_str:
                        var_value = self.state.memory.load(var_loc)
                        self.constrainBytes(self.state,var_value,var_loc,position,var_value_length)
                        print("[+] Vulnerable path found {}".format(vuln_string))
                        self.state.globals['type'] = "Format"
                        self.state.globals['position'] = position
                        self.state.globals['length'] = greatest_count
                        
                        return True
                if state_copy.globals['inputType'] == "ARG":
                    arg = state_copy.globals['arg']
                    arg_str = str(state_copy.solver.eval(arg,cast_to=str))
                    if str_val in arg_str:
                        var_value = self.state.memory.load(var_loc)
                        self.constrainBytes(self.state,var_value,var_loc,position,var_value_length)
                        print("[+] Vulnerable path found {}".format(vuln_string))
                        self.state.globals['type'] = "Format"
                        self.state.globals['position'] = position
                        self.state.globals['length'] = greatest_count
                        return True
 
        return False


    def constrainBytes(self, state, symVar, loc,position, length, strVal="%x_"):
        for i in range(length):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i).get_byte(0)
            constraint = state.se.And(strVal[strValIndex] == curr_byte)
            if (state.se.satisfiable(extra_constraints=[constraint])):
                state.add_constraints(constraint)
            else:
                print("[~] Byte {} not constrained to {}".format(i,strVal[strValIndex]))

    def run(self):
        if not self.checkExploitable():
            return super(type(self), self).run()

def checkFormat(binary_name,inputType="STDIN"):

    p = angr.Project(binary_name,load_options={"auto_load_libs": False})

    p.hook_symbol('printf',printFormat)

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

    run_environ = {}
    run_environ['type'] = None
    end_state = None
    #Lame way to do a timeout
    try:
        @timeout_decorator.timeout(120)
        def exploreBinary(simgr):
            simgr.explore(find=lambda s: 'type' in s.globals)

        exploreBinary(simgr)
        if 'found' in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            run_environ['type'] = end_state.globals['type']
            run_environ['position'] = end_state.globals['position']
            run_environ['length'] = end_state.globals['length']

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        print("[~] Format check timed out")
    if (inputType == "STDIN" or inputType == "LIBPWNABLE")and end_state is not None:
        stdin_str = str(end_state.posix.dumps(0))
        print("[+] Triggerable with STDIN : {}".format(stdin_str))
        run_environ['input'] = stdin_str
    elif inputType == "ARG" and end_state is not None:
        arg_str = str(end_state.solver.eval(arg,cast_to=str))
        run_environ['input'] = arg_str
        print("[+] Triggerable with arg : {}".format(arg_str))
       
    return run_environ


    
