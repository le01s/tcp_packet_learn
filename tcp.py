import dpkt
import socket
import struct
import binascii



ip = dpkt.ip.IP()

ip.src = socket.inet_aton("192.168.1.2")
ip.dst = socket.inet_aton("192.168.1.1")
ip.p = dpkt.ip.IP_PROTO_TCP


tcp = dpkt.tcp.TCP()
tcp.sport = 12345
tcp.dport = 80
tcp.seq = 100
tcp.flags = dpkt.tcp.TH_SYN

tcp.data = b'Data'

ip.data = tcp

packet = ip.pack()
print(packet)

def to_hex(packet):
    return ''.join(f'{byte:02x} ' for byte in packet)

hex_data = to_hex(packet)

print(hex_data)

hex_data_without__ = hex_data.replace(" ", "")

byte_data = binascii.unhexlify(hex_data_without__)

print("Raw bytes:", byte_data)


def parse_ip_header(packet):
    # Разбор IP-заголовка (первые 20 байт)
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])

    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    total_length = ip_header[2]
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])

    return {
        "Version": version,
        "Header Length": ihl * 4,
        "Total Length": total_length,
        "TTL": ttl,
        "Protocol": protocol,
        "Source IP": src_ip,
        "Destination IP": dst_ip
    }

def parse_tcp_header(packet):
    # Разбор TCP-заголовка (следующие 20 байт после IP-заголовка)
    tcp_header_start = 20
    tcp_header = struct.unpack('!HHLLBBHHH', packet[tcp_header_start:tcp_header_start+20])

    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq_num = tcp_header[2]
    ack_num = tcp_header[3]
    data_offset_reserved_flags = tcp_header[4]
    flags = tcp_header[5]
    window_size = tcp_header[6]

    return {
        "Source Port": src_port,
        "Destination Port": dst_port,
        "Sequence Number": seq_num,
        "Acknowledgment Number": ack_num,
        "Data Offset": (data_offset_reserved_flags >> 4) * 4,
        "Flags": flags,
        "Window Size": window_size
    }




print(parse_tcp_header(packet))
print(parse_ip_header(packet))