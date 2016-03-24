"""
USEAGE:
    Takes 2 arguements
    [1] HOSTNAME
    [2] MAX NUMBER OF PACKETS TO SEND TO EACH hop

    The code line below sends 3 packets to each hop
        between this machine and the destination host

    e.g. sudo python icmp.py google.com 3

"""

from socket import *
import struct 
import sys
import random
import time

ICMP_ECHO_REQUEST = 8

def checksum(source_string):
    """ Calculates the checksum of the data 
        inside your packet 
    """
    checksum = 0
    count_to = len(source_string) & -2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        checksum += this_val
        checksum &= 0xffffffff 
        count += 2
    if count_to < len(source_string):
        checksum += ord(source_string[len(source_string) - 1])
        checksum &= 0xffffffff  
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    answer = ~checksum
    answer &= 0xffff
    return answer >> 8 | (answer << 8 & 0xff00)

def create_packet(id):
    """Creates a new echo request packet based on the given "id"."""
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = 192 * "Q"

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, htons(checksum(header + data)), id, 1)
    return header + data

def main(dest_name, max_tries):
    dest_addr = gethostbyname(dest_name)        #get ip from host
    port = 33434                                #port on which we receive packets
    max_hops = 30
    icmp = getprotobyname('icmp')
    udp = getprotobyname('udp')
    ttl = 1                                     #start with TTL of 1

    print "\nTracing route to %s [%s] \nover a maximum of %d hops: \n" % (dest_name,dest_addr,max_hops)

    while True:
        print '{:>2}   '.format(ttl),

        #create 2 sockets, both raw, one to receive, one to send
        recv_socket = socket(AF_INET, SOCK_RAW, icmp)
        send_socket = socket(AF_INET, SOCK_RAW, icmp)

        #set value of ttl for the packet
        send_socket.setsockopt(SOL_IP, IP_TTL, ttl)
        
        # after this much time, we stop waiting for response
        max_timeout = struct.pack("ll", 3, 0)
        
        # Set the receive timeout so we behave more like regular traceroute
        recv_socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO, max_timeout)
        #bind socket to port
        recv_socket.bind(("", port))        
        curr_addr = None
        curr_name = None
        finished = False

        notAvail = 0;
        #stores RTT for multiple packets on the same hop
        dt = []
        #number of tries
        tries = max_tries
        #runs loop (max number of packets to send to one host)
        while tries > 0:
            #create packet_id, and then create packet
            packet_id = int(random.random() % 65535)
            packet = create_packet(packet_id)

            #send packet, the host as its destination
            send_socket.sendto(packet, (dest_name,1))   

            #start timer (to calculate RTT)         
            start = time.time()
            #due to some bug, timers dont work inside loops
            #so need nested loops

            while True:
                #try receiving packet
                #if timeout occurs, exception is raised
                #which is caught
                try:                    
                    _, curr_addr = recv_socket.recvfrom(512)
                    
                    #append RTT to RTT list
                    dt.append(str(int((time.time() - start) * 1000)) + " ms")
                    #extract address
                    curr_addr = curr_addr[0]

                    #extract host name, if there is one
                    try:
                        curr_name = gethostbyaddr(curr_addr)[0]
                    except error:
                        curr_name = curr_addr
                    break

                #if packet receive timesout    
                except error as (errno, errmsg):
                    dt.append("  *   ")
                    notAvail = 1
                    break
            #number of retries decreases
            tries = tries - 1
        
        #close sockets
        send_socket.close()
        recv_socket.close()
        
        if not finished:
            pass
        
        #if addr exists
        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = ""

        #lots of formatting
        #so it mimicks the way
        #tracert prints out in cmd, or bash

        outxx = ""
        for i in dt:
            outxx = outxx + "{:>7}   "
        abcd = "{:<70}"
        xx = outxx.format(*dt)
        print xx + abcd.format(curr_host)

        #increase ttl
        ttl += 1
        #if destination reached, or max_hops exceeded,
        #we end the loop
        if curr_addr == dest_addr or ttl > max_hops:
            break

#if invoked from cmdline
if __name__ == "__main__":
    #number of args should be 2
    if(len(sys.argv) != 3):
        print "\nUSAGE :\t\tsudo python icmp.py [address] [max_packets]"
        print "EXAMPLE :\tsudo python icmp.py google.com 3\n"
    else:
        #start running the tracert
        addr = sys.argv[1]
        num_tries = int(sys.argv[2])
        main(addr, num_tries)
