import socket
import struct

from formatter import Formatter


class bcolors:
    NETWORK_LAYER = '\033[94m'
    APP_LAYER = '\033[92m'
    LINK_LAYER = '\033[93m'
    TRANSPORT_LAYER = '\033[91m'
    ENDC = '\033[0m'


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    i = 7
    while True:
        raw_data, address = connection.recvfrom(65535)
        handle_link_layer(raw_data)

        print('\n')


def handle_link_layer(data):
    dest_mac, src_mac, eth_proto, data = unpack_ethernet(data)
    print(bcolors.LINK_LAYER + 'Ethernet Frame: ')
    print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}' + bcolors.ENDC)
    handle_network_layer(data, eth_proto)


def handle_network_layer(packet, eth_proto):
    print(bcolors.NETWORK_LAYER)
    if eth_proto == '0x800':
        version, header_length, ttl, next_header, src, target, data = unpack_ipv4(packet)
        print('\tIPv4 Packet: ')
        print(
            f'\tVersion: {version}, Header Length: {header_length}, Time To Live: {ttl}, Protocol: {next_header}, Source IP: {src}, Destination: {target}')
        handle_transport_layer(data, next_header)
    elif eth_proto == '0x86dd':
        version, traffic_class, flow_label, payload_length, next_header, hop_limit \
            , src_ip, dest_ip, data = unpack_ipv6(packet)
        print('\tIPv6 Packet: ')
        print(
            f'\tVersion: {version}, Traffic Class: {traffic_class}, Flow Label: {flow_label}, Payload Length: {payload_length}, '
            f'Next Header: {next_header}, Hop Limit: {hop_limit}, Src IP: {src_ip}, Dest IP: {dest_ip}')
        handle_transport_layer(data, next_header)
    elif eth_proto == '0x806':
        print('\tARP Packet: ')

    print(bcolors.ENDC)


def handle_transport_layer(packet, proto):
    print(bcolors.TRANSPORT_LAYER)
    if proto == 1:
        icmp_type, code, checksum = struct.unpack('! B B H', packet[:4])
        packet = packet[4:]
        print('\t\tICMP Packet: ')
        print(f'\t\t icmp_type: {icmp_type}, code: {code}, checksum: {checksum}')
    elif proto == 6:
        src_port, dest_port, seq_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, packet = unpack_tcp(
            packet)
        print('\t\tTCP Packet: ')
        print(
            f'\t\tsrc_port: {src_port}, dest_port: {dest_port}, sequence: {seq_num}, acknowledgment: {ack}, flag_urg: {flag_urg}, '
            f'flag_ack: {flag_ack}, flag_psh: {flag_psh}, flag_rst: {flag_rst}, flag_syn {flag_syn}, flag_fin: {flag_fin}')

        handle_app_layer(packet, src_port, dest_port)
    elif proto == 17:
        src_port, dest_port, size = struct.unpack('! H H 2x H', packet[:8])
        packet = packet[8:]
        print('\t\tUDP Packet: ')
        print(
            f'\t\tsrc_port: {src_port}, dest_port: {dest_port}, size: {size}')

    print(bcolors.ENDC)


def handle_app_layer(packet, src_port, dest_port):
    # HTTP
    if src_port == 80 or dest_port == 80:
        print(bcolors.APP_LAYER)
        print("\t\t\t HTTP Packet: " )
        print("\t\t\t" + packet.decode("unicode_escape"))
        print(bcolors.ENDC)
    # SSH
    elif (src_port == 22 or dest_port == 22) and len(packet) >= 4:
        packet_length, encrypted_packet, mac = unpack_ssh(packet)
        print(bcolors.APP_LAYER)
        print("\t\t\t SSH Packet: ")
        print(f"\t\t\t packet_length: {packet_length}, encrypted_packet: {encrypted_packet}, mac: {mac}")
        print(bcolors.ENDC)


def unpack_ssh(data):
    packet_length = (struct.unpack('! I', data[:4]))[0]
    encrypted_packet = (data[4:packet_length]).hex()
    mac = Formatter.format_mac_address(data[packet_length: 20])
    return packet_length, encrypted_packet, mac


def unpack_ipv6(data):
    first_word, payload_length, next_header, hop_limit = struct.unpack("! I H B B", data[:8])

    bin(first_word)
    "{0:b}".format(first_word)
    version = first_word >> 28
    traffic_class = (first_word >> 16) & 4095
    flow_label = int(first_word) & 65535

    src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dest_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

    return version, traffic_class, flow_label, payload_length, next_header, hop_limit \
        , Formatter.format_ipv6_address(src_ip), Formatter.format_ipv6_address(dest_ip), data[40:]


def unpack_ethernet(data):
    """
    Unpacking a ethernet frame
    :param data:
    :return:
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return Formatter.format_mac_address(dest_mac), Formatter.format_mac_address(src_mac), hex(proto), data[14:]


def unpack_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, Formatter.format_ipv4_address(src), Formatter.format_ipv4_address(
        target), data[header_length:]


def unpack_tcp(data):
    src_port, dest_port, seq_num, ack, offset_reserved_flag = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = (offset_reserved_flag & 1)
    return src_port, dest_port, seq_num, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


if __name__ == '__main__':
    main()
