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
