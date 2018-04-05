"""
Very quick and dirty way to generate RSA and EC keys
and header files for the ArduinoJWT
You can look at keys in the terminal and double check that headers has been
properly generated via following commands:
    openssl rsa -in rsa_private.pem -text -noout
    openssl ec -in ec_private.pem -text -noout

This file needs refactoring. Also might be better to have keys in JWK format.
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


if __name__ == '__main__':
    ### RSA ###
    file = open('rsa_keys.h', 'w')
    file.write('\n')
    file.write('#ifndef _rsa_keys_h\n')
    file.write('#define _rsa_keys_h\n')

    # Generate RSA private key, public key and certificate
    os.system('openssl genrsa -out rsa_private.pem 2048')
    os.system('openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem')
    os.system('openssl req -x509 -new -key rsa_private.pem -days 1000000 -out rsa_cert.pem -subj "/CN=unused"')

    with open('rsa_private.pem', 'r') as f:
        private_key = f.read()

    if isinstance(private_key, str):
        private_key = private_key.encode('utf-8')

    # Read keys
    private_key = load_pem_private_key(private_key, password=None, backend=default_backend())
    public_key = private_key.public_key()

    # Extract numbers
    private_key = private_key.private_numbers()
    public_key = private_key.public_numbers

    private_names = ['p', 'q', 'd', 'dmp1', 'dmq1', 'iqmp']
    for name in private_names:
        value = getattr(private_key, name)
        file.write('\nunsigned char ' + name + '[] = {\n0x')
        value_str = ''.join('{:02X}'.format(value))
        value_list = re.findall('..', value_str)
        file.write(', 0x'.join(value_list))
        file.write('\n};\n')

        length = len(value_list)
        file.write('unsigned int ' + name + '_len = {};\n'.format(length))

    # TODO: Public Exponent (e) does not print properly.
    # It's length is 5 bytes, 2.5 words, does not divide properly...
    public_names = ['n', 'e']
    for name in public_names:
        value = getattr(public_key, name)
        file.write('\nunsigned char ' + name + '[] = {\n0x')
        value_str = ''.join('{:02X}'.format(value))
        value_list = re.findall('..', value_str)
        file.write(', 0x'.join(value_list))
        file.write('\n};\n')

        length = len(value_list)
        file.write('unsigned int ' + name + '_len = {};\n'.format(length))

    file.write('\n#endif\n')
    file.close()

    ### EC ###
    file = open('ec_keys.h', 'w')
    file.write('\n')
    file.write('#ifndef _ec_keys_h\n')
    file.write('#define _ec_keys_h\n')

    # Generate EC private key, public key and certificate
    os.system('openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem')
    os.system('openssl ec -in ec_private.pem -pubout -out ec_public.pem')
    os.system('openssl req -x509 -new -key ec_private.pem -days 1000000 -out ec_cert.pem -subj "/CN=unused"')

    with open('ec_private.pem', 'r') as f:
        private_key = f.read()

    if isinstance(private_key, str):
        private_key = private_key.encode('utf-8')

    # Read keys
    private_key = load_pem_private_key(private_key, password=None, backend=default_backend())
    public_key = private_key.public_key()

    # Extract bytes
    private_key = private_key.private_numbers().private_value
    public_key = public_key.public_numbers()

    file.write('\nunsigned char ec_private[] = {\n0x')
    value_str = ''.join('{:02X}'.format(private_key))
    value_list = re.findall('..', value_str)
    file.write(', 0x'.join(value_list))
    file.write('\n};\n')

    length = len(value_list)
    file.write('unsigned int ec_private_len = {};\n'.format(length))

    file.write('\nunsigned char ec_public[] = {\n0x')
    value_str = ''.join('{:02X}'.format(public_key.x))
    value_list = re.findall('..', value_str)
    length = len(value_list)
    file.write(', 0x'.join(value_list))
    file.write(',\n0x')
    value_str = ''.join('{:02X}'.format(public_key.y))
    value_list = re.findall('..', value_str)
    length += len(value_list)
    file.write(', 0x'.join(value_list))
    file.write('\n};\n')

    file.write('unsigned int ec_public_len = {};\n'.format(length))

    file.write('\n#endif\n')
    file.close()
