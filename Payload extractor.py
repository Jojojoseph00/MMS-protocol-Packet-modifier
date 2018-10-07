# Mokthari Youssef El-Moukhtar 2018 @SUTD
#
# This script uses scapy to extract payload from a packet and convert to Binary


from scapy.all import *
import dpkt
import struct

t0 = time.time()
lengths = {}
count = 0
pkts = PcapReader("captureIED_11.09(system-off).pcapng")
                # File name, ensure your target file is correctly identified
index = []


def hexdump1(x, dump=False):
    # function to convert to binary
    s = ""
    x = raw(x)
    l = len(x)
    i = 0
    while i < l:
        for j in range(16):
            if i + j < l:
                s += "%02X" % orb(x[i + j])
                s += ""
            if j % 16 == 7:
                s += ""
            # DO NOT include a space, will falsify binary conversion
        i += 16
    if s.endswith("\n"):
        s = s[:-1]
    return s


while (True):
    pkt = pkts.read_packet()
    # '172.16.1.11'
    if pkt is None or count > 2:
                # This means 
        break
    else:

        if (pkt.haslayer('IP') and pkt[IP].src == '172.16.1.11'):
            # Source IP, can be changed as needed
            print("\n\n//=================START OF PACKET=================// \n\n")
            pkt.show()
            hexadecimal = hexdump1(pkt[Raw])
            print(type(hexadecimal))
            temp = int(hexadecimal, 16)
            print("\n\----Below is the Hexadecimal payload:")
            print(temp)
            print("\n\----Below is the Binary payload:")
            print(bin(temp))
            print("\n//==================END OF PACKET==================// \n\n")
            count += 1
            pkt[Raw] = '111111'

pkts.close()

# print(lengths.keys())
# print(lengths.values())
# print(set(index))
# print(time.time()-t0)
