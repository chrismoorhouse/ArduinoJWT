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

#include "ArduinoJWT.h"
#include "uECC.h"
#include "base64.h"
#include "sha256.h"

#include <stdio.h>
#include <string.h>

// The standard JWT header already base64 encoded.
const char* jwtHeader[3] PROGMEM = {
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",       // {"typ":"JWT","alg":"HS256"}
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",       // {"typ":"JWT","alg":"RS256"}
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"        // {"typ":"JWT","alg":"ES256"}
};

// const uint8_t SHA256_SIG[] PROGMEM = {
//   0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
//   0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
// };

// typedef struct SHA256_CTX {
// 	uint32_t	state[8];
// 	uint64_t	bitcount;
// 	uint8_t	buffer[BLOCK_LENGTH];
// } SHA256_CTX;

typedef struct SHA256_HashContext{
    uECC_HashContext uECC;
    // SHA256_CTX ctx;
} SHA256_HashContext;

static void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    // SHA256_Init(&context->ctx);
    Sha256.init();
}

static void update_SHA256(const uECC_HashContext *base, const uint8_t* message, unsigned int message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    // SHA256_Update(&context->ctx, message, (int) message_size);
    Sha256.print((char*) message);
}

static void finish_SHA256(const uECC_HashContext *base, uint8_t *hash) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    // SHA256_Final(hash, &context->ctx);
    hash = Sha256.result();
}

// ArduinoJWT Methods
void ArduinoJWT::setPSK(String psk) {
  _psk = psk;
}

void ArduinoJWT::setPSK(char* psk) {
  _psk = String(psk);
}

// void ArduinoJWT::setRSAPK(String buf){
//   setRSAPK((uint8_t*) buf.c_str(), buf.length());
// }
//
// void ArduinoJWT::setRSAPK(uint8_t* buf, int len){
//   // asn1_get_private_key(buf, len, &_rsa_ctx);
// }

void ArduinoJWT::setPK(String pk) {
  setPK((uint8_t*) pk.c_str());
}

void ArduinoJWT::setPK(uint8_t* pk) {
  _pk = pk;
}

int ArduinoJWT::getJWTLength(String payload, Algo algo) {
  return getJWTLength((char*)payload.c_str(), algo);
}

int ArduinoJWT::getJWTLength(char* payload, Algo algo) {
  return strlen(jwtHeader[algo]) + encode_base64_length(strlen(payload)) + encode_base64_length(32) + 2;
}

int ArduinoJWT::getJWTPayloadLength(String jwt) {
  return getJWTPayloadLength((char*)jwt.c_str());
}

// void ArduinoJWT::freeRSAPK(){
//   RSA_free(&_rsa_ctx);
// }

int ArduinoJWT::getJWTPayloadLength(char* jwt) {
  char jwtCopy[strlen(jwt)];
  memcpy((char*)jwtCopy, jwt, strlen(jwt));
    // Get all three jwt parts
  const char* sep = ".";
  char* token;
  token = strtok(jwtCopy, sep);
  token = strtok(NULL, sep);
  if(token == NULL) {
    return -1;
  } else {
    return decode_base64_length((uint8_t*)token) + 1;
  }
}

String ArduinoJWT::encodeJWT(String payload, Algo algo)
{
  char jwt[getJWTLength(payload, algo)];
  encodeJWT((char*)payload.c_str(), (char*)jwt, algo);
  return String(jwt);
}

void ArduinoJWT::encodeJWT(char* payload, char* jwt, Algo algo)
{
  uint8_t* ptr = (uint8_t*)jwt;

  // Build the header part of the jwt (header.payload)
  memcpy(ptr, jwtHeader[algo], strlen(jwtHeader[algo]));
  ptr += strlen(jwtHeader[algo]);
  *ptr++ = '.';

  // Build the payload part of the jwt (header.payload)
  int payload_len = strlen(payload);
  encode_base64((uint8_t*) payload, payload_len, ptr);
  ptr += encode_base64_length(payload_len);
  // Get rid of any padding (trailing '=' added when base64 encoding)
  while(*(ptr - 1) == '=') {
    ptr--;
  }
  *(ptr) = 0;

  // Build the signature
  uint8_t* signature;
  unsigned int signature_len;

  // Hash the message (jwt without jws) if needed
  uint8_t *hash;
  if (algo == RS256 || algo == ES256) {
    // TODO: Should check if message is too long..
    Sha256.init();
    Sha256.print(jwt);
    hash = Sha256.result();
  }

  switch(algo) {
    case HS256:
      signature_len = 32;
      // Perform HMAC
      Sha256.initHmac((const uint8_t*)_psk.c_str(), _psk.length());
      Sha256.print(jwt);
      signature = Sha256.resultHmac();
      break;

    case RS256:
      // // RSA
      // // https://github.com/igrr/axtls-8266/blob/d94ccb9181401e03aed051d7657c790ea935413a/ssl/gen_cert.c#L300
      // // https://github.com/igrr/axtls-8266/blob/0c3a9f722f11799fbeda1f99f9d9ab77a82a4489/crypto/rsa.c#L261
      // // https://tools.ietf.org/html/rfc3447#section-9.2
      //
      // // Create pad (refered as T in RFC)
      // uint8_t *pad;
      // int pad_size;
      //
      // pad_size = sizeof(SHA256_SIG) + HASH_LENGTH;
      // pad = (uint8_t *)malloc(pad_size);
      // memcpy(pad, SHA256_SIG, sizeof(SHA256_SIG));
      // memcpy(&pad[sizeof(SHA256_SIG)], hash, HASH_LENGTH);
      //
      // // Allocate memory for the signature
      // signature = (uint8_t *)malloc(_rsa_ctx.num_octets);
      //
      // // Sign
      // signature_len = RSA_encrypt((const RSA_CTX*) &_rsa_ctx, pad, pad_size, signature, 1);
      //
      // // Get rid of the pad
      // free(pad);
      break;

    case ES256:
      // ECC
      // https://github.com/kmackay/micro-ecc/blob/master/uECC.h
      uint8_t sig[64] = {0};

      // Sign deterministic
      uint8_t tmp[2 * HASH_LENGTH + BLOCK_LENGTH];
      SHA256_HashContext ctx = {{
          &init_SHA256,
          &update_SHA256,
          &finish_SHA256,
          BLOCK_LENGTH,
          HASH_LENGTH,
          tmp
      }};

      // Sign hash
      uECC_sign_deterministic(
        (const uint8_t*) _pk,                           // private key
        (const uint8_t*) hash, HASH_LENGTH,             // hash
        &ctx.uECC,                                      // ecc context
        sig,                                            // signature output
        uECC_secp256r1()                                // curve
      );

      // Output
      signature = sig;
      signature_len = 64;
      break;
  }

  // Add the signature to the jwt
  *ptr++ = '.';
  encode_base64(signature, signature_len, ptr);
  ptr += encode_base64_length(signature_len);
  // Get rid of any padding and replace / and +
  while(*(ptr - 1) == '=') {
    ptr--;
  }
  *(ptr) = 0;

  // if (algo == RS256){
  //   // Original signature is not needed anymore
  //   free(signature);
  // }

}

String ArduinoJWT::decodeJWT(String jwt)
{
  String payload;

  int payloadLength = getJWTPayloadLength(jwt);
  if(payloadLength > 0)
  {
    char jsonPayload[payloadLength];
    if(decodeJWT((char*)jwt.c_str(), (char*)jsonPayload, payloadLength)) {
      payload = String(jsonPayload);
    }
  }
  return payload;
}

bool ArduinoJWT::decodeJWT(char* jwt, char* payload, int payloadLength) {
  // Get all three jwt parts
  const char* sep = ".";
  char* encodedHeader = strtok(jwt, sep);
  char* encodedPayload = strtok(NULL, sep);
  char* encodedSignature = strtok(NULL, sep);

  // Check all three jwt parts exist
  if(encodedHeader == NULL || encodedPayload == NULL || encodedSignature == NULL)
  {
    payload = NULL;
    return false;
  }

  // Build the signature
  Sha256.initHmac((const uint8_t*)_psk.c_str(), _psk.length());
  Sha256.print(encodedHeader);
  Sha256.print(".");
  Sha256.print(encodedPayload);

  // Encode the signature as base64
  uint8_t base64Signature[encode_base64_length(32)];
  encode_base64(Sha256.resultHmac(), 32, base64Signature);
  uint8_t* ptr = &base64Signature[0] + encode_base64_length(32);
  // Get rid of any padding and replace / and +
  while(*(ptr - 1) == '=') {
    ptr--;
  }
  *(ptr) = 0;

  // Do the signatures match?
  if(strcmp((char*)encodedSignature, (char*)base64Signature) == 0) {
    // Decode the payload
    decode_base64((uint8_t*)encodedPayload, (uint8_t*)payload);
    payload[payloadLength - 1] = 0;
    return true;
  } else {
    payload = NULL;
    return false;
  }
}
