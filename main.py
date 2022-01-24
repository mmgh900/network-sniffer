import socket
import struct
import textwrap


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f'\nEthernet Frame: Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}, Data: {data}')


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]


# Formats MAC address to proper format
def get_mac_address(bytes_address):
    bytes_string = map('{:02x}'.format, bytes_address)
    mac_address = ':'.join(bytes_address).upper()


if __name__ == '__main__':
    main()
