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
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
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


class Response(object):
    def __init__(self):
        self.max_rtt = None
        self.min_rtt = None
        self.avg_rtt = None
        self.packet_lost = None
        self.ttl = None
        self.ret_code = None

        self.packet_size = None
        self.timeout = None
        self.destination = None
        self.destination_ip = None


class Ping(object):
    def __init__(self, destination, timeout=1000, packet_size=55, own_id=None, quiet_output=True, udp=False, bind=None):
        self.response = Response()
        self.response.destination = destination
        self.response.timeout = timeout
        self.response.packet_size = packet_size

        self.destination = destination
        self.timeout = timeout
        self.packet_size = packet_size
        self.udp = udp
        self.bind = bind
        self.ttl = None

        if own_id is None:  # 标识符， 用于区分响应是否是自己的
            self.own_id = os.getpid() & 0xFFFF
        else:
            self.own_id = own_id

        try:
            # FIXME: Use destination only for display this line here? see: https://github.com/jedie/python-ping/issues/3
            self.dest_ip = to_ip(self.destination)
            if quiet_output:
                self.response.destination_ip = self.dest_ip
        except socket.gaierror as e:
            pass

        self.seq_number = 0
        self.send_count = 0
        self.receive_count = 0
        self.min_time = 999999999
        self.max_time = 0.0
        self.ttl = 128
        self.total_time = 0.0

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

    def run(self, count=None, deadline=None):
        """
        循环执行
        """
        while True:
            if self.udp:
                delay = self.do_udp()
            else:
                delay = self.do()

            self.seq_number += 1
            if count and self.seq_number >= count:
                break
            if deadline and self.total_time >= deadline:
                break

            if delay == None:
                delay = 0

            # Pause for the remainder of the MAX_SLEEP period (if applicable)
            if (MAX_SLEEP > delay):
                time.sleep((MAX_SLEEP - delay) / 1000.0)

        return self.response

    def do_udp(self):
        current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        send_time = self.send_one_udp_ping(current_socket)
        if send_time == None:
            return
        self.send_count += 1

        receive_time, packet_size, ip, ip_header = self.receive_one_udp_ping(current_socket)
        if receive_time:
            self.receive_count += 1
            delay = (receive_time - send_time) * 1000.0
            self.total_time += delay
            if self.min_time > delay:
                self.min_time = delay
            if self.max_time < delay:
                self.max_time = delay
            self.ttl = int(ip_header['ttl'])
            return delay
        else:
            pass
        current_socket.close()

    def do(self):
        """
        Send one ICMP ECHO_REQUEST and receive the response until self.timeout
        """
        try:  # One could use UDP here, but it's obscure

            current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

            # Bind the socket to a source address
            if self.bind:
                current_socket.bind((self.bind, 0))  # Port number is irrelevant for ICMP

        except socket.error as exc:
            if exc.errno == 1:
                # Operation not permitted - Add more information to traceback
                etype, evalue, etb = sys.exc_info()
                evalue = etype(
                    "%s - Note that ICMP messages can only be send from processes running as root." % evalue
                )
                six.reraise(etype, evalue, etb)
            raise  # raise the original error

        send_time = self.send_one_icmp_ping(current_socket)
        if send_time == None:
            return
        self.send_count += 1

        receive_time, packet_size, ip, ip_header, icmp_header = self.receive_one_icmp_ping(current_socket)
        current_socket.close()

        if receive_time:
            self.receive_count += 1
            delay = (receive_time - send_time) * 1000.0
            self.total_time += delay
            if self.min_time > delay:
                self.min_time = delay
            if self.max_time < delay:
                self.max_time = delay
            self.ttl = int(ip_header['ttl'])
            return delay
        else:
            pass

    def send_one_udp_ping(self, current_socket):

        # zero = 0
        #
        # protocol = socket.IPPROTO_UDP
        #
        # data = "hello udp".encode('utf-8')
        #
        # udp_length = 8 + len(data)
        #
        # checksum = 0
        # pseudo_header = struct.pack('!BBH', zero, protocol, udp_length)
        # pseudo_header = src_ip + dest_ip + pseudo_header
        # udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
        # checksum = checksum_func(pseudo_header + udp_header + data)
        # udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)

        send_time = default_timer()
        packet = "hello udp".encode('utf-8')

        try:
            current_socket.sendto(packet, (self.destination, 31500))
        except socket.error as e:
            current_socket.close()
            return

        return send_time

    def send_one_icmp_ping(self, current_socket):
        """
        Send one ICMP ECHO_REQUEST
        """
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0

        # Make a dummy header with a 0 checksum.
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
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
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
        )

        packet = header + data

        send_time = default_timer()

        try:
            current_socket.sendto(packet, (self.destination, 31500))  # Port number is irrelevant for ICMP
        except socket.error as e:
            self.response.output.append("General failure (%s)" % (e.args[1]))
            current_socket.close()
            return

        return send_time

    def receive_one_udp_ping(self, current_socket):
        timeout = self.timeout / 1000.0
        while True:  # 尝试接收响应，直到超时
            select_start = default_timer()
            # 使用linux的select进行IO
            inputready, outputready, exceptready = select.select([current_socket], [], [], timeout)
            select_duration = (default_timer() - select_start)

            packet_data, address = current_socket.recvfrom(MAX_RECV)
            receive_time = default_timer()

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
            return receive_time, packet_size, ip, ip_header

    def receive_one_icmp_ping(self, current_socket):
        """
        接收一次ping请求的响应
        :param current_socket: 当前使用的socket
        :return:
        """
        timeout = self.timeout / 1000.0

        while True:  # 尝试接收响应，直到超时
            select_start = default_timer()
            inputready, outputready, exceptready = select.select([current_socket], [], [], timeout)
            select_duration = (default_timer() - select_start)
            if inputready == []:  # timeout
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

            timeout = timeout - select_duration
            if timeout <= 0:
                return None, 0, 0, 0, 0


def ping(hostname, timeout=1000, count=3, packet_size=55, *args, **kwargs):
    p = Ping(hostname, timeout, packet_size, *args, **kwargs)
    return p.run(count)
