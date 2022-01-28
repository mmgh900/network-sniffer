class Formatter:

    @staticmethod
    def format_mac_address(bytes_address):
        """
        This function formats MAC address in XX:XX:XX:XX:XX style
        :param bytes_address:
        :return:
        """
        bytes_string = map('{:02x}'.format, bytes_address)
        mac_address = ':'.join(bytes_string).upper()
        return mac_address

    @staticmethod
    def format_ipv4_address(address):
        return '.'.join(map(str, address))

    @staticmethod
    def format_ipv6_address(address):
        return address
