from __future__ import print_function
import argparse
import logging
logging.disable(logging.CRITICAL)
from lib import formatDetector
from lib import formatLeak
from lib import inputDetector
from lib import overflowDetector
from lib import overflowExploiter
from lib import overflowExploitSender
from lib import protectionDetector
from lib import winFunctionDetector
from lib import formatExploiter

logging.getLogger().disabled = True
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file',help="File to analyze")
    parser.add_argument('-l','--libc',help="libc to use")
    parser.add_argument('-u','--url',help="Remote URL to pwn",default="")
    parser.add_argument('-p','--port',help="Remote port to pwn",default="0")
    parser.add_argument('-v','--verbose',help="Verbose mode",action="store_true",default=False)

    args = parser.parse_args()
    if args.file is None:
        print("[-] Exitting no file specified")
        exit(1)
    if args.verbose:
        logging.disable(logging.CRITICAL)

    #Detect problem type
    properties = {}
    properties['input_type'] = inputDetector.checkInputType(args.file)
    properties['libc'] = args.libc
    properties['file'] = args.file
    print("[+] Checking pwn type...")
    print("[+] Checking for overflow pwn type...")
    properties['pwn_type'] = overflowDetector.checkOverflow(args.file,inputType=properties['input_type'])
    if properties['pwn_type']['type'] is None:
        print("[+] Checking for format string pwn type...")
        properties['pwn_type'] = formatDetector.checkFormat(args.file,inputType=properties['input_type'])

    #Get problem mitigations 
    print("[+] Getting binary protections")
    properties['protections'] = protectionDetector.getProperties(args.file)

    #Is it a leak based one?
    if properties['pwn_type']['type'] == "Format":
        print("[+] Checking for flag leak")
        properties['pwn'] = formatLeak.checkLeak(args.file,properties)
        #Launch leak remotely
        if properties['pwn']['flag_found'] and args.url is not "":
            print("[+] Found flag through leaks locally. Launching remote exploit")
            print("[+] Connecting to {}:{}".format(args.url,args.port))
            properties['pwn']['exploit'] = formatLeak.checkLeak(args.file,properties,remote_server=True,remote_url=args.url,port_num=int(args.port))
        if properties['pwn']['flag_found']:
            exit(0)


    #Is there an easy win function
    properties['win_functions'] = winFunctionDetector.getWinFunctions(args.file)

    #Exploit overflows
    if properties['pwn_type']['type'] == "Overflow":
        print("[+] Exploiting overflow")
        properties['pwn_type']['results'] = overflowExploiter.exploitOverflow(args.file, properties, inputType=properties['input_type'])
        if properties['pwn_type']['results']['input']:
            properties['send_results'] = overflowExploitSender.sendExploit(args.file,properties)
            if properties['send_results']['flag_found'] and args.url is not "":
                properties['remote_results'] = overflowExploitSender.sendExploit(args.file,properties,remote_server=True,remote_url=args.url,port_num=int(args.port))

    elif properties['pwn_type']['type'] == "Format":
        properties['pwn_type']['results'] = formatExploiter.exploitFormat(args.file,properties)
        if properties['pwn_type'] is not None and 'flag_found' in properties['pwn_type'].keys() and properties['pwn_type']['results']['flag_found'] and args.url is not "":
            properties['pwn_type']['send_results'] = formatExploiter.getRemoteFormat(properties,remote_url=args.url,remote_port=int(args.port))
    else:
        print("[-] Can not determine vulnerable type")

if __name__ == '__main__':
    main()
