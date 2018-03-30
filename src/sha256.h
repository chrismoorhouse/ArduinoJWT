/**
 * Based on original work by Cathedrow
 * Original library located at https://github.com/Cathedrow/Cryptosuite
 */

#ifndef Sha256_h
#define Sha256_h

#include <inttypes.h>
#include "Print.h"

#define HASH_LENGTH 32
#define BLOCK_LENGTH 64

#define BUFFER_SIZE 64

const uint32_t sha256K[] PROGMEM = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

const unsigned char sha256InitState[] PROGMEM = {
  0x67,0xe6,0x09,0x6a, // H0
  0x85,0xae,0x67,0xbb, // H1
  0x72,0xf3,0x6e,0x3c, // H2
  0x3a,0xf5,0x4f,0xa5, // H3
  0x7f,0x52,0x0e,0x51, // H4
  0x8c,0x68,0x05,0x9b, // H5
  0xab,0xd9,0x83,0x1f, // H6
  0x19,0xcd,0xe0,0x5b  // H7
};

union _buffer {
  unsigned char b[BLOCK_LENGTH];
  uint32_t w[BLOCK_LENGTH/4];
};
union _state {
  unsigned char b[HASH_LENGTH];
  uint32_t w[HASH_LENGTH/4];
};

class Sha256Class : public Print
{
  public:
    void init(void);
    void initHmac(const unsigned char* secret, int secretLength);
    unsigned char* result(void);
    unsigned char* resultHmac(void);
    virtual size_t write(unsigned char);
    using Print::write;
  private:
    void pad();
    void addUncounted(unsigned char data);
    void hashBlock();
    uint32_t ror32(uint32_t number, unsigned char bits);
    _buffer buffer;
    unsigned char bufferOffset;
    _state state;
    uint32_t byteCount;
    unsigned char keyBuffer[BLOCK_LENGTH];
    unsigned char innerHash[HASH_LENGTH];
};
extern Sha256Class Sha256;

#endif
