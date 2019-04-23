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


union _buffer {
  uint8_t b[BLOCK_LENGTH];
  uint32_t w[BLOCK_LENGTH/4];
};
union _state {
  uint8_t b[HASH_LENGTH];
  uint32_t w[HASH_LENGTH/4];
};

class Sha256 : public Print
{
  public:
    void init(void);
    uint8_t* result(void);
    virtual size_t write(uint8_t);
    using Print::write;
  private:
    void pad();
    void addUncounted(uint8_t data);
    void hashBlock();
    uint32_t ror32(uint32_t number, uint8_t bits);
    _buffer buffer;
    uint8_t bufferOffset;
    _state state;
    uint32_t byteCount;

};

class HMAC : public Sha256
{
  public:
    void init(const uint8_t* secret, int secretLength);
    uint8_t* result(void);

  private:
    uint8_t keyBuffer[BLOCK_LENGTH];        // K0 in FIPS-198a
    uint8_t innerHash[HASH_LENGTH];

};

#endif
