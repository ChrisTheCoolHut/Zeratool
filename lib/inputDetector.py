import angr
import IPython

stdin = "STDIN"
arg = "ARG"
libpwnable = "LIBPWNABLE"

def checkInputType(binary_name):

    #Check for libpwnableharness
    p = angr.Project(binary_name)
    if any(['libpwnable' in str(x.binary) for x in p.loader.all_elf_objects]):
        return libpwnable

    p = angr.Project(binary_name,load_options={"auto_load_libs": False})

#    CFG = p.analyses.CFGFast()

    #Functions which MIGHT grab from STDIN
    reading_functions = ['fgets','gets','scanf','read']
#    binary_functions = [str(x[1].name) for x in CFG.kb.functions.items()]
    binary_functions = p.loader.main_object.imports.keys()

    #Match reading functions against local functions
    if any([x in reading_functions for x in binary_functions]):
        return "STDIN"
    return "ARG"

