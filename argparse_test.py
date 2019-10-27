# 导入argparse模块
import argparse
# 新建一个ArgumentParser对象，description是对命令行解析的一个描述信息，通常在使用-h命令时显示
parser = argparse.ArgumentParser(description="Process some integers.")
# 增加一个参数
parser.add_argument('-p', dest='port', type = int, help = 'An port number!')
# 解析命令行输入
args = parser.parse_args()
print("Port: ", args.port)