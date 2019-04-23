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


// ArduinoJWT Related
typedef enum Algo{
  HS256=0,
  RS256=1,
  ES256=2
}Algo;

class ArduinoJWT {
private:
  // for HS256 (Pre-shared Key)
  String psk;

  // RS256 (RSA Keys)
  // RSA_CTX rsa_ctx;

  // ES256 (Private Key, Public Key)
  uint8_t* ec_private;
  uint8_t* ec_public;

public:
  // Set keys for encoding and decoding JWTs
  void setHS256key(String psk);
  void setHS256key(char* psk);

  // void setRS256keys(String buf);
  // void setRS256keys(uint8_t *buf, int len);

  // // Dump keys if they are not needed
  // void freeRSAPK();

  // More than welcome to use this function if setRS256keys does not work out
  // RSA_priv_key_new(rsa_ctx,
  //        modulus, mod_len, pub_exp, pub_len, priv_exp, priv_len,
  //        p, p_len, q, p_len, dP, dP_len, dQ, dQ_len, qInv, qInv_len);

  void setES256keys(String ec_private, String ec_public);
  void setES256keys(uint8_t* ec_private, uint8_t* ec_public);

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
  String decodeJWT(String jwt, Algo algo);
  bool decodeJWT(char* jwt, char* payload, int payloadLength, Algo algo);
};

#endif
