"""
Very quick and dirty way to generate RSA and EC keys as well as header files for the ArduinoJWT.
You can look at keys in the terminal and double check that headers has been
properly generated via following commands:
    openssl rsa -in rsa_private.pem -text -noout
    openssl ec -in ec_private.pem -text -noout

This file might need a bit more refactoring. Also might be better to have keys in JWK format.
But we will leave that task for the near future.
Python3 have been tested. Not sure if python2 will work properly.
So be warned!

Almost forgot, make sure openssl installed on your system!

Author: https://github.com/Barmaley13
Date: 04/04/2018
"""

import os
import re
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend


def to_hex_ascii(value):
    """ Convert binary value to hex representation in ascii """
    output = ''

    # Format value to hex in ascii
    value_str = '{:02X}'.format(value)

    # Append zero if needed
    if len(value_str) % 2:
        value_str = '0' + value_str

    # Merge into 16 bit values
    value_list = re.findall('..', value_str)

    # Add '0x' prefix
    value_list = ['0x' + v for v in value_list]

    # Add newline to every 8th byte
    value_list = ['\n' + v if i != 0 and i % 8 == 0 else v for i, v in enumerate(value_list)]

    # Merge with comas
    output += ', '.join(value_list)

    output += ',\n'

    return output, len(value_list)


def c_wrapper(name, hex_ascii, length):
    """ Puts C wrapper around hex representation """
    # Start header
    output = '\n'
    output += 'unsigned char {}[] = {{\n'.format(name)

    # Add hex_ascii to this hamburger
    output += hex_ascii

    # Finish header
    output += '};\n'
    output += 'unsigned int {}_len = {};\n'.format(name, length)

    return output


def to_c_header(name, value):
    """ Convert name, value pair to C/C++ header """
    # Create hex representation of the value
    hex_ascii, length = to_hex_ascii(value)
    output = c_wrapper(name, hex_ascii, length)

    return output


if __name__ == '__main__':
    ### RSA ###
    # Generate RSA private key, public key and certificate
    os.system('openssl genrsa -out rsa_private.pem 2048')
    os.system('openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem')
    os.system('openssl req -x509 -new -key rsa_private.pem -days 1000000 -out rsa_cert.pem -subj "/CN=unused"')

    # Read private key from pem file
    with open('rsa_private.pem', 'r') as f:
        private_key = f.read()

    if isinstance(private_key, str):
        private_key = private_key.encode('utf-8')

    # Load keys as crypto instance
    private_key = load_pem_private_key(private_key, password=None, backend=default_backend())
    public_key = private_key.public_key()

    # Extract numbers
    private_key = private_key.private_numbers()
    public_key = private_key.public_numbers

    # Start writing to a header file
    file = open('rsa_keys.h', 'w+')
    file.write('\n')
    file.write('#ifndef _rsa_keys_h\n')
    file.write('#define _rsa_keys_h\n')

    # Print private key
    private_names = ['p', 'q', 'd', 'dmp1', 'dmq1', 'iqmp']
    for name in private_names:
        value = getattr(private_key, name)
        header_str = to_c_header(name, value)
        file.write(header_str)

    # Print public key
    public_names = ['n', 'e']
    for name in public_names:
        value = getattr(public_key, name)
        header_str = to_c_header(name, value)
        file.write(header_str)

    # Finish writing to a header file
    file.write('\n#endif\n')
    file.close()

    ### EC ###
    # Generate EC private key, public key and certificate
    os.system('openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem')
    os.system('openssl ec -in ec_private.pem -pubout -out ec_public.pem')
    os.system('openssl req -x509 -new -key ec_private.pem -days 1000000 -out ec_cert.pem -subj "/CN=unused"')

    # Read private key from pem file
    with open('ec_private.pem', 'r') as f:
        private_key = f.read()

    if isinstance(private_key, str):
        private_key = private_key.encode('utf-8')

    # Load keys as crypto instance
    private_key = load_pem_private_key(private_key, password=None, backend=default_backend())
    public_key = private_key.public_key()

    # Extract numbers
    private_key = private_key.private_numbers()
    public_key = public_key.public_numbers()

    # Start writing to a header file
    file = open('ec_keys.h', 'w+')
    file.write('\n')
    file.write('#ifndef _ec_keys_h\n')
    file.write('#define _ec_keys_h\n')

    # Print private key
    header_str = to_c_header('ec_private', private_key.private_value)
    file.write(header_str)

    # Print public key
    hex_ascii_x, length_x = to_hex_ascii(public_key.x)
    hex_ascii_y, length_y = to_hex_ascii(public_key.y)

    hex_ascii = hex_ascii_x + hex_ascii_y
    length = length_x + length_y

    header_str = c_wrapper('ec_public', hex_ascii, length)
    file.write(header_str)

    # Finish writing to a header file
    file.write('\n#endif\n')
    file.close()
