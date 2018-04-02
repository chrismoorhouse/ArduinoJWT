/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include "hmac.h"
#include "keys.h"

#include <stdio.h>
#include <string.h>


typedef struct SHA256_HashContext{
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

static void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_init(&context->ctx);
}

static void update_SHA256(const uECC_HashContext *base, const uint8_t* message, unsigned int message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_update(&context->ctx, message, (int) message_size);
}

static void finish_SHA256(const uECC_HashContext *base, uint8_t *hash) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    sha256_final(&context->ctx, hash);
}

void setup(){
    Serial.begin(115200);
    Serial.println();

    // Hash the message (jwt)
    String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
    SHA256_CTX ctx;
    uint8_t hash[HASH_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t*) jwt, strlen(jwt));
    sha256_final(&ctx, buf);

    int i, c;
    uint8_t sig[64] = {0};

    uint8_t tmp[2 * HASH_SIZE + BLOCK_SIZE];
    SHA256_HashContext ctx = {{
        &init_SHA256,
        &update_SHA256,
        &finish_SHA256,
        BLOCK_SIZE,
        HASH_SIZE,
        tmp
    }};

    const struct uECC_Curve_t * curve;
    curve = uECC_secp256r1();

    Serial.println("Testing signature");

    // if (!uECC_make_key(ec_public, ec_private, curves[c])) {
    //     Serial.println("uECC_make_key() failed\n");
    // }
    // memcpy(hash, ec_public, HASH_SIZE);

    if (!uECC_sign_deterministic(ec_private, hash, HASH_SIZE, &ctx.uECC, sig, curve)) {
        Serial.println("uECC_sign() failed");
    }else{
        Serial.println("uECC_sign() success!");
    }

    if (!uECC_verify(ec_public, hash, HASH_SIZE, sig, curve)) {
        Serial.println("uECC_verify() failed");
    }else{
        Serial.println("uECC_verify() success!");
    }

    Serial.println("");

}

void loop(){
  // Main code here
}
