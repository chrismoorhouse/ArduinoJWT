/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include "sha256.h"
#include "keys.h"

#include <stdio.h>
#include <string.h>


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

void setup(){
    Serial.begin(115200);
    Serial.println();

    // Hash the message (payload) if needed
    String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
    uint8_t *hash;
    Sha256.init();
    Sha256.print(jwt);
    hash = Sha256.result();

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
