import socket
import argparse
from threading import Thread

'''
1. 第一步，编写主函数
创建socket，绑定所有网络地址和58868端口并开始监听；
新开一个线程等待客户端的连接，以免阻塞我们输入命令（注意）
'''
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 58868))
    s.listen(1024)
    # TODO
    t = Thread(target=waitConnect, args(s,))
    t.start

'''
2. 第二步
将新开的线程中连接进来的socket添加到一个list中
并检查一下socket长度，需要至少一个客户端连接
'''
print('Wait at least a client connection!')
# 若没有客户端连接，则
while not len(socketList):
    pass
print('It has been a client connection!)


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
            # TODO
            sendCmd(cmd_str)


'''
4. 第四步,实现等待客户端的函数
循环等待客户端连接，并判断socket是否在socketList已存储过，没有则添加
'''
def waitConnect(s):
    while True:
        sock, addr = s.accept()
        if sock not in socketList:
            socketList.append(socket)


'''
5. 第五步，实现发送命令的函数
便利socketList，将每个socket都调用一次send将命令发送出去
'''
def sendCmd(cmd):
    print("Send command......")
    for sock in socketList:
        sock.send(cmd.encode = ('UTF-8'))