from pydbg import *
from pydbg.defines import *
import sys
import os
import struct


dbg = pydbg();
#define process to debug
debugee = "client.exe"
foundpid = False



class recvData:
    pass

def recv_handler(dbg):
    #read in the stack trace
    addr_buf = dbg.read_process_memory(dbg.Context.Esp+ 0xC, 4)
    prevlen = dbg.read_process_memory(dbg.Context.Esp + 0x10, 4)
    buf_data = struct.unpack("<{0}B".format(prevlen),addr_buf)[0]
    print "Data received at {:X} with data {}".format(addr_buf,buf_data)
    return DBG_CONTINUE

def attachtoproc(dbg):
    for (pid,name) in dbg.enumerate_processes():
        if( name.lower() == debugee):
            foundpid = True
            print 'Found pid {} for process {}'.format(pid,name)
            dbg.attach(pid)
            recvaddr = dbg.func_resolve_debuggee("ws2_32.dll","recv")
            print "Address to recv is {}".format(recvaddr)
            dbg.bp_set(recvaddr,description="recv_bp",handler=recv_handler)
    return
        
def main():
    print "NetAnal, tool for automatic network analysis genuine & hunter"
    while True:
        try:
            attachtoproc(dbg)
            dbg.debug_event_loop()
            '''
            pydbg.load(dbg,debugee)
            print "opening the process for debug"
            recvaddr = dbg.func_resolve_debuggee("ws2_32.dll","recv")
            print "Address to recv is {}".format(recvaddr)
            dbg.bp_set(recvaddr,description="recv_bp",handler=recv_handler)
            dbg.debug_event_loop()
            '''
        except pdx:
            pass
        
    
    return


if __name__ == '__main__':
    main()
