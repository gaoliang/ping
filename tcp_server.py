# coding=utf-8
from socket import *
import select

tcpSocket = socket(AF_INET, SOCK_STREAM)
tcpSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
addres = ('', 8888)
tcpSocket.bind(addres)
tcpSocket.listen(5)

inputs = [tcpSocket]
runing = True

while True:
    '''当select遍历inputs中的对象，如果出现了可读的情况（select中参数检测的以此是可读、可写、异常）时，
    会将那些可读的对象放到readabled的List中，例如：客户端新建一个链接，那个inputs中的tcpSocket变为可读
    的对象，就会添加到readabled中。并且等待到资源可用的时候，才进行唤醒'''
    readabled, writeabled, exceptional = select.select(inputs, [], [])

    for socket in readabled:
        if socket == tcpSocket:
            conn, addr = tcpSocket.accept()
            # 如果是一个客户端connect创建，服务器的会有一个监听套接字可用。进而把监听套接字中的conn加入列表中，以便下次循环。
            inputs.append(conn)
            print('%s已经连入系统' % str(addr))
        else:
            data = socket.recv(1024)
            socket.send('hi! I am  TCP server'.encode('utf-8'))
            if data:
                print(data)
            else:
                inputs.remove(socket)
                socket.close()
    if not runing:
        break

tcpSocket.close()
