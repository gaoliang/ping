import socket

zero = 0
protocol = 31500
addr = ('127.0.0.1', protocol)
size = 2048

with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as s:
    s.bind(addr)
    while True:
        data, src_addr = s.recvfrom(size)
        print(data)
