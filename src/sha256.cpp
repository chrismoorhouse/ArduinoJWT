/**
 * Based on original work by Cathedrow
 * Original library located at https://github.com/Cathedrow/Cryptosuite
 */

#include <string.h>
#include "sha256.h"


void Sha256Class::init(void) {
  memcpy_P(state.b,sha256InitState,32);
  byteCount = 0;
  bufferOffset = 0;
}

uint32_t Sha256Class::ror32(uint32_t number, unsigned char bits) {
  return ((number << (32-bits)) | (number >> bits));
}

void Sha256Class::hashBlock() {
  // Sha256 only for now
  unsigned char i;
  uint32_t a,b,c,d,e,f,g,h,t1,t2;

  a=state.w[0];
  b=state.w[1];
  c=state.w[2];
  d=state.w[3];
  e=state.w[4];
  f=state.w[5];
  g=state.w[6];
  h=state.w[7];

  for (i=0; i<64; i++) {
    if (i>=16) {
      t1 = buffer.w[i&15] + buffer.w[(i-7)&15];
      t2 = buffer.w[(i-2)&15];
      t1 += ror32(t2,17) ^ ror32(t2,19) ^ (t2>>10);
      t2 = buffer.w[(i-15)&15];
      t1 += ror32(t2,7) ^ ror32(t2,18) ^ (t2>>3);
      buffer.w[i&15] = t1;
    }
    t1 = h;
    t1 += ror32(e,6) ^ ror32(e,11) ^ ror32(e,25); // ?1(e)
    t1 += g ^ (e & (g ^ f)); // Ch(e,f,g)
    t1 += pgm_read_dword(sha256K+i); // Ki
    t1 += buffer.w[i&15]; // Wi
    t2 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22); // ?0(a)
    t2 += ((b & c) | (a & (b | c))); // Maj(a,b,c)
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  state.w[0] += a;
  state.w[1] += b;
  state.w[2] += c;
  state.w[3] += d;
  state.w[4] += e;
  state.w[5] += f;
  state.w[6] += g;
  state.w[7] += h;
}

void Sha256Class::addUncounted(unsigned char data) {
  buffer.b[bufferOffset ^ 3] = data;
  bufferOffset++;
  if (bufferOffset == BUFFER_SIZE) {
    hashBlock();
    bufferOffset = 0;
  }
}

size_t Sha256Class::write(unsigned char data) {
  ++byteCount;
  addUncounted(data);
  return( 1 );
}

void Sha256Class::pad() {
  // Implement SHA-256 padding (fips180-2 §5.1.1)

  // Pad with 0x80 followed by 0x00 until the end of the block
  addUncounted(0x80);
  while (bufferOffset != 56) addUncounted(0x00);

  // Append length in the last 8 bytes
  addUncounted(0); // We're only using 32 bit lengths
  addUncounted(0); // But SHA-1 supports 64 bit lengths
  addUncounted(0); // So zero pad the top bits
  addUncounted(byteCount >> 29); // Shifting to multiply by 8
  addUncounted(byteCount >> 21); // as SHA-1 supports bitstreams as well as
  addUncounted(byteCount >> 13); // byte.
  addUncounted(byteCount >> 5);
  addUncounted(byteCount << 3);
}


unsigned char* Sha256Class::result(void) {
  // Pad to complete the last block
  pad();

  // Swap byte order back
  for (int i=0; i<8; i++) {
    uint32_t a,b;
    a=state.w[i];
    b=a<<24;
    b|=(a<<8) & 0x00ff0000;
    b|=(a>>8) & 0x0000ff00;
    b|=a>>24;
    state.w[i]=b;
  }

  // Return pointer to hash (20 characters)
  return state.b;
}


#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

unsigned char keyBuffer[BLOCK_LENGTH]; // K0 in FIPS-198a
unsigned char innerHash[HASH_LENGTH];

void Sha256Class::initHmac(const unsigned char* key, int keyLength) {
  unsigned char i;
  memset(keyBuffer,0,BLOCK_LENGTH);
  if (keyLength > BLOCK_LENGTH) {
    // Hash long keys
    init();
    for (;keyLength--;) write(*key++);
    memcpy(keyBuffer,result(),HASH_LENGTH);
  } else {
    // Block length keys are used as is
    memcpy(keyBuffer,key,keyLength);
  }
  //for (i=0; i<BLOCK_LENGTH; i++) debugHH(keyBuffer[i]);
  // Start inner hash
  init();
  for (i=0; i<BLOCK_LENGTH; i++) {
    write(keyBuffer[i] ^ HMAC_IPAD);
  }
}

unsigned char* Sha256Class::resultHmac(void) {
  unsigned char i;
    // Complete inner hash
  memcpy(innerHash,result(),HASH_LENGTH);
  // now innerHash[] contains H((K0 xor ipad)||text)

  // Calculate outer hash
  init();
  for (i=0; i<BLOCK_LENGTH; i++) write(keyBuffer[i] ^ HMAC_OPAD);
  for (i=0; i<HASH_LENGTH; i++) write(innerHash[i]);
  return result();
}
Sha256Class Sha256;
