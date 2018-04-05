/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include "sha256.h"
#include "../keys/ec_keys.h"

#include <stdio.h>
#include <string.h>


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

void setup(){
    Serial.begin(115200);
    Serial.println();

    // Hash the message (jwt)
    String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
    Sha256 sha256;
    sha256.init();
    sha256.print(jwt);
    hash = sha256.result();

    int i, c;
    uint8_t sig[64] = {0};

    uint8_t tmp[2 * HASH_LENGTH + BLOCK_LENGTH];
    SHA256_HashContext ctx = {{
        &init_SHA256,
        &update_SHA256,
        &finish_SHA256,
        BLOCK_LENGTH,
        HASH_LENGTH,
        tmp
    }};

    const struct uECC_Curve_t * curve;
    curve = uECC_secp256r1();

    Serial.println("Testing signature");

    // if (!uECC_make_key(ec_public, ec_private, curves[c])) {
    //     Serial.println("uECC_make_key() failed\n");
    // }
    // memcpy(hash, ec_public, HASH_LENGTH);

    if (!uECC_sign_deterministic(ec_private, hash, HASH_LENGTH, &ctx.uECC, sig, curve)) {
        Serial.println("uECC_sign() failed");
    }else{
        Serial.println("uECC_sign() success!");
    }

    if (!uECC_verify(ec_public, hash, HASH_LENGTH, sig, curve)) {
        Serial.println("uECC_verify() failed");
    }else{
        Serial.println("uECC_verify() success!");
    }

    Serial.println("");

}

void loop(){
  // Main code here
}
