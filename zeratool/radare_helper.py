import r2pipe
import json
import os


def getRegValues(filename, endAddr):

    r2 = r2pipe.open(filename,flags=["-d"])
    #r2.cmd("doo")
    r2.cmd("e dbg.bep=entry")
    entry_addr = json.loads(r2.cmd("iej"))[0]["vaddr"] 
    r2.cmd("dcu {}".format(entry_addr))
    regs = json.loads(r2.cmd("drj"))
    r2.quit()
    return regs


def get_base_addr(filename):

    r2 = r2pipe.open(filename)
    r2.cmd("doo")
    base_addr = json.loads(r2.cmd("iMj"))["vaddr"]
    r2.quit()
    return base_addr


"""
This is so hacky. I'm sorry
It's also only for stdin
"""


def findShellcode(filename, endAddr, shellcode, commandInput):

    hex_str = shellcode[:4]
    hex_str = "".join([hex(x).replace("0x", "") for x in hex_str])

    abs_path = os.path.abspath(filename)

    # If you know a better way to direct stdin please let me know
    os.system("env > temp.env")
    with open("command.input", "wb") as f:
        f.write(commandInput)
    with open("temp.rr2", "w") as f:
        # f.write(
        #     "program={}\nstdin=command.input\nenvfile={}\n".format(filename, "temp.env")
        # )
            f.write("program={}\nstdin=command.input\nclearenv=true\nenvfile={}\n".format(abs_path,"temp.env"))

    r2 = r2pipe.open(filename)
    r2.cmd("e dbg.profile = temp.rr2")
    r2.cmd("ood")
    r2.cmd("dcu {}".format(endAddr))
    r2.cmd("s ebp")
    r2.cmd("e search.maxhits =1")
    r2.cmd("e search.in=dbg.map")  # Need to specify this for r2pipe

    loc = json.loads(r2.cmd("/xj {}".format(hex_str)))

    # Cleaning up
    if os.path.exists("command.input"):
        os.remove("command.input")
    if os.path.exists("temp.rr2"):
        os.remove("temp.rr2")
    if os.path.exists("temp.env"):
        os.remove("temp.env")

    return loc[0]
