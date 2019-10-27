import socket
# 创建socket对象，AF_INET表示使用IPV4对象，SOCK_STREAM表示使用的是基于流
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(('192.168.43.61', 7786))