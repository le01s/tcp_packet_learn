from scapy.all import sniff

# def to_hex(packet):
#     return ''.join(f'{byte:02x} ' for byte in bytes(packet))

def packet_handler(packet):
    # hex_output = to_hex(packet)
    print(packet)


sniff(iface='eno1:', prn=packet_handler, filter='', store=0)