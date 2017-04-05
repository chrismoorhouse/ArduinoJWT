# Arduino JSON Web Token Library

Library for encoding and decoding JSON web tokens for the Arduino and ESP8266 platforms.

## Limitations

 - It is not currently possible to add options such as expiry time, user etc to the JWT
 - The header is fixed to be {"alg": "HS256", "typ": "JWT"}

## Compatible Hardware

 - Arduino
 - Intel Galileo/Edison
 - ESP8266

## License

This code is released under the BSD 3 Clause License.

## Special Thanks

This library uses extracts from the following libraries:
 - Base64 Encoding: https://github.com/Densaugeo/base64_arduino by Densaugeo
 - HMAC-SHA256 Cryptography: https://github.com/Cathedrow/Cryptosuite by Cathedrow
