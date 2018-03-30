/**

 Copyright (c) 2016, Interior Automation Ltd.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation and/or
    other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors may be
    used to endorse or promote products derived from this software without specific prior
    written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 **/

#ifndef ARDUINO_JWT_H
#define ARDUINO_JWT_H

#include "Arduino.h"

// // Some crazy hacks to compile this shit
// #define CONFIG_SSL_CERT_VERIFICATION
//
// #include "../lib/axtls-8266/crypto/bigint_impl.h"
// #include "../lib/axtls-8266/crypto/bigint.h"
// #include "../lib/axtls-8266/crypto/os_int.h"
// #include "../lib/axtls-8266/crypto/crypto.h"


// The standard JWT header already base64 encoded.
const String jwtHeader[3] PROGMEM = {
  "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9",   // {"alg": "HS256", "typ": "JWT"}
  "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9",   // {"alg": "RS256", "typ": "JWT"}"
  "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9"    // {"alg": "ES256", "typ": "JWT"}
};

// const uint8_t SHA256_SIG[] PROGMEM = {
//   0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
//   0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
// };


// ArduinoJWT Related
enum Algo {HS256=0, RS256=1, ES256=2};

class ArduinoJWT {
private:
  String _psk;        // for HS256 (Pre-shared Key)
  // RSA_CTX _rsa_ctx;   // for RS256 (RSA Private Key)
  String _pk;         // for ES256 (Private Key)

public:
  // Set keys for encoding and decoding JWTs
  void setPSK(String psk);
  void setPSK(char* psk);
  // void setRSAPK(String buf);
  // void setRSAPK(uint8_t *buf, int len);
  void setPK(String pk);
  void setPK(char* pk);

  // // Dump keys if they are not needed
  // void freeRSAPK();

  // More than welcome to use this function if setRSAPK does not work out
  // RSA_priv_key_new(rsa_ctx,
  //        modulus, mod_len, pub_exp, pub_len, priv_exp, priv_len,
  //        p, p_len, q, p_len, dP, dP_len, dQ, dQ_len, qInv, qInv_len);

  // Get the calculated length of a JWT
  int getJWTLength(String payload, Algo algo);
  int getJWTLength(char* payload, Algo algo);
  // Get the length of the decoded payload from a JWT
  int getJWTPayloadLength(String jwt);
  int getJWTPayloadLength(char* jwt);
  // Create a JSON Web Token
  String encodeJWT(String payload, Algo algo);
  void encodeJWT(char* payload, char* jwt, Algo algo);
  // Decode a JWT and retreive the payload
  String decodeJWT(String jwt);
  bool decodeJWT(char* jwt, char* payload, int payloadLength);
};

#endif
