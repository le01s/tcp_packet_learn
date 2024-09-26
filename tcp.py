import dpkt
import socket
import struct
import binascii


def parse_udp_header(packet):
    udp_header_start = 20
    udp_header = struct.unpack('!HHHH', packet[udp_header_start:udp_header_start+8])

    src_port = udp_header[0]
    dst_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]

    data_start = udp_header_start + 8
    data = packet[data_start:data_start + (length - 8)]

    return {
        "Source Port": src_port,
        "Destination Port": dst_port,
        "Length": length,
        "Checksum": checksum,
        "Data" : data
    }

def parse_tcp_header(packet):
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

def parse_ip_header(packet):
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

def binascii_data(data):
    return binascii.unhexlify(data)

def hex_to_read(data):
    return data.replace(" ", "")

def to_hex(packet):
    return ''.join(f'{byte:02x} ' for byte in packet)

def gen_tcp():
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
    return ip

def gen_udp():
    ip = dpkt.ip.IP()

    ip.src = socket.inet_aton("192.168.1.2")
    ip.dst = socket.inet_aton("192.168.1.1")
    ip.p = dpkt.ip.IP_PROTO_UDP


    tcp = dpkt.udp.UDP()
    tcp.sport = 12345
    tcp.dport = 80
    tcp.seq = 100
    tcp.flags = dpkt.udp.UDP_HDR_LEN

    tcp.data = b'Data'

    ip.data = tcp
    return ip

ip_tcp = gen_tcp()
ip_udp = gen_udp()
print(f'UDP: {ip_udp}')


packet_tcp = ip_tcp.pack()
packet_udp = ip_udp.pack()

print(f'Packet TCP: {packet_tcp}')
print(f'Packet UDP: {packet_udp}')

hex_data_tcp = to_hex(packet_tcp)
hex_data_udp = to_hex(packet_udp)

print(f'HEX-data TCP: {hex_data_tcp}')
print(f'HEX-data UDP: {hex_data_udp}')

print(f'RAW data TCP: {hex_to_read(hex_data_tcp)}')
print(f'RAW data UDP: {hex_to_read(hex_data_udp)}')

print(f'BINASCII TCP: {binascii_data(hex_to_read(hex_data_tcp))}')
print(f'BINASCII UDP: {binascii_data(hex_to_read(hex_data_udp))}')

print(f'READ IP HEADER TCP: {parse_ip_header(packet_tcp)}')
print(f'READ main TCP: {parse_tcp_header(packet_tcp)}')

print(f'READ IP HEADER UDP: {parse_ip_header(packet_udp)}')
print(f'READ main UDP: {parse_udp_header(packet_udp)}')