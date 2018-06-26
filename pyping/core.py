# coding: utf-8

import os
import select
import six
import socket
import struct
import sys
import time

if sys.platform.startswith("win32"):
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

# ICMP parameters
ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)

MAX_RECV = 2048  # Max size of incoming buffer
MAX_SLEEP = 1000


def calculate_checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    while count < countTo:
        if sys.byteorder == "little":
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        if not six.PY3:
            loByte = ord(loByte)
            hiByte = ord(hiByte)
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string):  # Check for odd length
        loByte = source_string[len(source_string) - 1]
        if not six.PY3:
            loByte = ord(loByte)
        sum += loByte

    sum &= 0xffffffff  # Truncate sum to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)  # Add high 16 bits to low 16 bits
    sum += (sum >> 16)  # Add carry from above (if any)
    answer = ~sum & 0xffff  # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer


def is_valid_ip4_address(addr):
    parts = addr.split(".")
    if not len(parts) == 4:
        return False
    for part in parts:
        try:
            number = int(part)
        except ValueError:
            return False
        if number > 255 or number < 0:
            return False
    return True


def to_ip(addr):
    if is_valid_ip4_address(addr):
        return addr
    return socket.gethostbyname(addr)


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


class Ping(object):
    def __init__(self, destination, timeout=1000, packet_size=55, own_id=None, udp=False, tcp=False, bind=None):
        self.destination = destination
        self.timeout = timeout
        self.packet_size = packet_size
        self.udp = udp
        self.tcp = tcp

        if own_id is None:  # 标识符， 用于区分响应是否是自己的
            self.own_id = os.getpid() & 0xFFFF
        else:
            self.own_id = own_id

        try:
            # FIXME: Use destination only for display this line here? see: https://github.com/jedie/python-ping/issues/3
            self.dest_ip = to_ip(self.destination)
        except socket.gaierror as e:
            pass

    def header2dict(self, names, struct_format, data):
        """
        将一个ip或icmp请求的二进制响应解析成结构体 dict
        :param names: 结构体的字段
        :param struct_format: 结构体的格式
        :param data: 二进制响应
        :return: 生成的字典
        """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))

    # --------------------------------------------------------------------------
    def ping(self):
        if self.udp:
            return self.ping_udp()
        elif self.tcp:
            return self.ping_tcp()
        else:
            return self.ping_icmp()

    def ping_icmp(self):
        try:
            current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        except socket.error as exc:  # 需要root权限
            if exc.errno == 1:
                etype, evalue, etb = sys.exc_info()
                evalue = etype(
                    "%s - Note that ICMP messages can only be send from processes running as root." % evalue
                )
                six.reraise(etype, evalue, etb)
            raise

        send_time = self.send_icmp_ping(current_socket)
        receive_time, packet_size, ip, ip_header, icmp_header = self.receive_icmp_ping(current_socket)
        current_socket.close()

        if receive_time:
            delay = (receive_time - send_time) * 1000.0
            ttl = int(ip_header['ttl'])
            return {
                'delay': delay,
                'ttl': ttl,
                'destination_ip': self.dest_ip,
                'self_ip': get_host_ip()
            }
        else:
            return None

    def send_icmp_ping(self, current_socket):
        """
        发送icmp的ECHO
        """
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0

        # Make a dummy header with a 0 checksum.
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, 0
        )

        padBytes = []
        startVal = 0x42
        for i in range(startVal, startVal + (self.packet_size)):
            padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
        data = bytes(padBytes)

        # Calculate the checksum on the data and the dummy header.
        checksum = calculate_checksum(header + data)  # Checksum is in network order

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, 0
        )

        packet = header + data
        send_time = default_timer()
        try:
            current_socket.sendto(packet, (self.destination, 31500))
        except socket.error as e:
            current_socket.close()
        return send_time

    def receive_icmp_ping(self, current_socket):
        """
        接收一次ping请求的响应
        :param current_socket: 当前使用的socket
        :return:
        """
        timeout = self.timeout / 1000.0
        input_ready = select.select([current_socket], [], [], timeout)
        if input_ready == []:  # timeout
            return None, 0, 0, 0, 0
        packet_data, address = current_socket.recvfrom(MAX_RECV)
        # 解析icmp数据报文
        icmp_header = self.header2dict(
            names=[
                "type", "code", "checksum",
                "packet_id", "seq_number"
            ],
            struct_format="!BBHHH",
            data=packet_data[20:28]
        )

        receive_time = default_timer()

        if icmp_header["packet_id"] == self.own_id:  # 自己的包
            # 解析ip数据报文
            ip_header = self.header2dict(
                names=[
                    "version", "type", "length",
                    "id", "flags", "ttl", "protocol",
                    "checksum", "src_ip", "dest_ip"
                ],
                struct_format="!BBHHHBBHII",
                data=packet_data[:20]  # ip数据包头部长度为20字节
            )
            packet_size = len(packet_data) - 28
            ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))
            return receive_time, packet_size, ip, ip_header, icmp_header

    def ping_udp(self, port=9999):
        current_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        current_socket.bind(('0.0.0.0', 0))

        send_time = self.send_udp_ping(current_socket, port)
        receive_time = self.receive_udp_ping(current_socket)
        from_port = current_socket.getsockname()[1]
        current_socket.close()

        if receive_time:
            delay = (receive_time - send_time) * 1000.0
            return {
                'delay': delay,
                'destination_ip': self.dest_ip,
                'from_port': from_port,
                'target_port': port,
                'self_ip': get_host_ip()
            }
        else:
            return None

    def send_udp_ping(self, current_socket, port):
        data = 'hello! UDP Server'
        send_time = default_timer()
        try:
            current_socket.sendto(data.encode('utf-8'), (self.destination, port))
        except socket.error:
            current_socket.close()
        return send_time

    def receive_udp_ping(self, current_socket):
        timeout = self.timeout / 1000.0
        receive_time = None
        ready = select.select([current_socket], [], [], timeout)
        if ready[0]:
            current_socket.recvfrom(1024)
            receive_time = default_timer()
        return receive_time

    def ping_tcp(self, port=8888):
        current_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        from_port = current_socket.getsockname()[1]
        send_time = self.send_tcp_ping(current_socket, port=port)
        receive_time = self.receive_tcp_ping(current_socket)
        current_socket.close()

        if receive_time:
            delay = (receive_time - send_time) * 1000.0
            return {
                'delay': delay,
                'destination_ip': self.dest_ip,
                'from_port': from_port,
                'target_port': port,
                'self_ip': get_host_ip()

            }
        else:
            return None

    def send_tcp_ping(self, current_socket, port):

        current_socket.connect((self.destination, port))
        data = 'hello! TCP Server'
        send_time = default_timer()
        try:
            current_socket.send(data.encode('utf-8'))
        except socket.error:
            current_socket.close()
        return send_time

    def receive_tcp_ping(self, current_socket):
        timeout = self.timeout / 1000.0
        receive_time = None
        ready = select.select([current_socket], [], [], timeout)
        if ready[0]:
            current_socket.recv(1024)
            receive_time = default_timer()
        return receive_time
