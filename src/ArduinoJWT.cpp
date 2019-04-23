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

#define ES256_SIG_LENGTH  64

// The standard JWT header already base64 encoded.
const char* jwtHeader[3] PROGMEM = {
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",       // {"alg":"HS256","typ":"JWT"}
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",       // {"alg":"RS256","typ":"JWT"}
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"        // {"alg":"ES256","typ":"JWT"}
};

// const uint8_t SHA256_SIG[] PROGMEM = {
//   0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
//   0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
// };

// // Debugging
// void printxstr(uint8_t* hex_str, unsigned int hex_str_len){
// 	for (int i=0; i<hex_str_len; i++) {
//     // Alignment
//     if (i!=0){
//       if (i%16 == 0){
//         Serial.println("");
//       }else{
//         Serial.print(" ");
//       }
//     }
//
//     Serial.print((hex_str[i] >> 4) & 0xF, HEX);
//     Serial.print(hex_str[i] & 0xF, HEX);
// 	}
//   Serial.println("");
// }

typedef struct SHA256_HashContext{
    uECC_HashContext uECC;
    Sha256 ctx;
} SHA256_HashContext;

static void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    context->ctx.init();
}

static void update_SHA256(const uECC_HashContext *base, const uint8_t* message, unsigned int message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    for(unsigned int i=0; i<message_size; i++){
      context->ctx.write(message[i]);
    }
}

static void finish_SHA256(const uECC_HashContext *base, uint8_t *hash) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    hash = context->ctx.result();
}

// ArduinoJWT Methods
void ArduinoJWT::setHS256key(String psk) {
  this->psk = psk;
}

void ArduinoJWT::setHS256key(char* psk) {
  this->psk = String(psk);
}

// void ArduinoJWT::setRS256keys(String buf){
//   setRS256keys((uint8_t*) buf.c_str(), buf.length());
// }
//
// void ArduinoJWT::setRS256keys(uint8_t* buf, int len){
//   // asn1_get_private_key(buf, len, &rsa_ctx);
// }
//
// void ArduinoJWT::freeRSAPK(){
//   RSA_free(&rsa_ctx);
// }

void ArduinoJWT::setES256keys(String ec_private, String ec_public) {
  setES256keys((uint8_t*) ec_private.c_str(), (uint8_t*) ec_public.c_str());
}

void ArduinoJWT::setES256keys(uint8_t* ec_private, uint8_t* ec_public) {
  this->ec_private = ec_private;
  this->ec_public = ec_public;
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
  uint8_t* ptr = (uint8_t*) jwt;

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
  uint8_t* signature = NULL;
  unsigned int signature_len;

  if (algo == HS256){
    // Perform HMAC
    HMAC hmac;
    hmac.init((const uint8_t*) psk.c_str(), psk.length());
    hmac.print(jwt);
    signature = hmac.result();
    signature_len = HASH_LENGTH;
  }

  if (algo == RS256 || algo == ES256) {
    // Hash the message (jwt without jws)
    // TODO: Should check if message is too long..
    uint8_t* hash;
    Sha256 sha256;
    sha256.init();
  	sha256.print(jwt);
  	hash = sha256.result();

    // // Debugging
    // Serial.println("JWT:");
    // Serial.println(jwt);
    // Serial.println("Hash: ");
    // printxstr(hash, HASH_LENGTH);

    // TODO: Get this compiled!
    // if (algo == RS256) {
    //   // RSA
    //   // https://github.com/igrr/axtls-8266/blob/d94ccb9181401e03aed051d7657c790ea935413a/ssl/gen_cert.c#L300
    //   // https://github.com/igrr/axtls-8266/blob/0c3a9f722f11799fbeda1f99f9d9ab77a82a4489/crypto/rsa.c#L261
    //   // https://tools.ietf.org/html/rfc3447#section-9.2
    //
    //   // Create pad (refered as T in RFC)
    //   uint8_t *pad;
    //   int pad_size;
    //
    //   pad_size = sizeof(SHA256_SIG) + HASH_LENGTH;
    //   pad = (uint8_t *)malloc(pad_size);
    //   memcpy(pad, SHA256_SIG, sizeof(SHA256_SIG));
    //   memcpy(&pad[sizeof(SHA256_SIG)], hash, HASH_LENGTH);
    //
    //   // Allocate memory for the signature
    //   signature = (uint8_t *)malloc(rsa_ctx.num_octets);
    //
    //   // Sign
    //   signature_len = RSA_encrypt((const RSA_CTX*) &rsa_ctx, pad, pad_size, signature, 1);
    //
    //   // Get rid of the pad
    //   free(pad);
    // }

    if (algo == ES256) {
      // ECC
      // https://github.com/kmackay/micro-ecc/blob/master/uECC.h
      signature_len = ES256_SIG_LENGTH;
      uint8_t sig[ES256_SIG_LENGTH];

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
        (const uint8_t*) ec_private,                    // private key
        (const uint8_t*) hash, HASH_LENGTH,             // hash
        &ctx.uECC,                                      // ecc context
        sig,                                            // signature output
        uECC_secp256r1()                                // curve
      );

      // Output
      signature = sig;

      // // Debugging
      // Serial.println("Signature: ");
      // printxstr(signature, signature_len);
    }

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

String ArduinoJWT::decodeJWT(String jwt, Algo algo)
{
  String payload;

  int payloadLength = getJWTPayloadLength(jwt);
  if(payloadLength > 0)
  {
    char jsonPayload[payloadLength];
    if(decodeJWT((char*)jwt.c_str(), (char*)jsonPayload, payloadLength, algo)) {
      payload = String(jsonPayload);
    }
  }
  return payload;
}

bool ArduinoJWT::decodeJWT(char* jwt, char* payload, int payloadLength, Algo algo) {
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

  if (algo == HS256) {
    // Build the signature
    uint8_t* signature;
    HMAC hmac;
    hmac.init((const uint8_t*) psk.c_str(), psk.length());
    hmac.print(encodedHeader);
    hmac.print(".");
    hmac.print(encodedPayload);
    signature = hmac.result();
    unsigned int signature_len = HASH_LENGTH;

    // Encode the signature as base64
    uint8_t base64Signature[encode_base64_length(signature_len)];
    encode_base64(signature, signature_len, base64Signature);
    uint8_t* ptr = &base64Signature[0] + encode_base64_length(signature_len);
    // Get rid of any padding and replace / and +
    while(*(ptr - 1) == '=') {
      ptr--;
    }
    *(ptr) = 0;

    // Do the signatures match?
    if(strcmp((char*) encodedSignature, (char*) base64Signature) == 0) {
      // Decode the payload
      decode_base64((uint8_t*)encodedPayload, (uint8_t*)payload);
      payload[payloadLength - 1] = 0;
      return true;
    }
  }

  // TODO: Write and test RSA decode section
  // if (algo == RS256){}

  if (algo == ES256) {
    // Decode the signature for verification
    unsigned int signature_len = ES256_SIG_LENGTH;
    uint8_t signature[signature_len];
    decode_base64((uint8_t*) encodedSignature, signature);
    // Shorten it if needed
    uint8_t sig[ES256_SIG_LENGTH];
    memcpy(sig, signature, ES256_SIG_LENGTH);

    // Hash the message (jwt without jws)
    String hash_input = String(encodedHeader) + String(sep) + String(encodedPayload);

    // // Debugging
    // Serial.println("Hash Input:");
    // Serial.println(hash_input);

    // TODO: Should check if message is too long..
    uint8_t* hash;
    Sha256 sha256;
    sha256.init();
    sha256.print(hash_input.c_str());
    hash = sha256.result();

    // Verify signature
    int verify = uECC_verify(
      (const uint8_t*) ec_public,                       // public key
      (const uint8_t*) hash, HASH_LENGTH,               // hash
      (const uint8_t*) sig,                             // signature
      uECC_secp256r1()                                  // curve
    );

    if (verify) {
      decode_base64((uint8_t*) encodedPayload, (uint8_t*) payload);
      payload[payloadLength - 1] = 0;
      return true;
    }
  }

  // If everything fails
  payload = NULL;
  return false;
}
