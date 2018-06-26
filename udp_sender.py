import socket

address = ('127.0.0.1', 31500)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

while True:
    msg = input().encode('utf8')
    if not msg:
        break
    s.sendto(msg, address)

s.close()
