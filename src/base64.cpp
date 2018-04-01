/**
 * Based on original work by Densaugeo
 * Original library located at https://github.com/Densaugeo/base64_arduino
 */

/**
 * Base64 encoding and decoding of strings. Uses '+' for 62, '\' for 63, '=' for padding
 * This has been modified to use '-' for 62, '_' for 63 as per the JWT specification
 */

#include "base64.h"

 uint8_t binary_to_base64(uint8_t v) {
   // Capital letters - 'A' is ascii 65 and base64 0
   if(v < 26) return v + 'A';

   // Lowercase letters - 'a' is ascii 97 and base64 26
   if(v < 52) return v + 71;

   // Digits - '0' is ascii 48 and base64 52
   if(v < 62) return v - 4;

   // '+' is ascii 43 and base64 62
   if(v == 62) return '-';

   // '/' is ascii 47 and base64 63
   if(v == 63) return '_';

   return 64;
 }

 uint8_t base64_to_binary(uint8_t c) {
   // Capital letters - 'A' is ascii 65 and base64 0
   if('A' <= c && c <= 'Z') return c - 'A';

   // Lowercase letters - 'a' is ascii 97 and base64 26
   if('a' <= c && c <= 'z') return c - 71;

   // Digits - '0' is ascii 48 and base64 52
   if('0' <= c && c <= '9') return c + 4;

   // '+' is ascii 43 and base64 62
   if(c == '-') return 62;

   // '/' is ascii 47 and base64 63
   if(c == '_') return 63;

   return 255;
 }


 unsigned int encode_base64_length(unsigned int input_length) {
   return (input_length + 2)/3*4;
 }

 unsigned int encode_base64_length(String input){
   return encode_base64_length((unsigned int) input.length());
 }

 unsigned int decode_base64_length(uint8_t input[]) {
   uint8_t *start = input;

   while(base64_to_binary(input[0]) < 64) {
     ++input;
   }

   unsigned int input_length = input - start;

   unsigned int output_length = input_length/4*3;

   switch(input_length % 4) {
     default: return output_length;
     case 2: return output_length + 1;
     case 3: return output_length + 2;
   }
 }

 unsigned int decode_base64_length(String input)
 {
   return decode_base64_length((uint8_t*) input.c_str());
 }

 unsigned int encode_base64(uint8_t input[], unsigned int input_length, uint8_t output[]) {
   unsigned int full_sets = input_length/3;

   // While there are still full sets of 24 bits...
   for(unsigned int i = 0; i < full_sets; ++i) {
     output[0] = binary_to_base64(                         input[0] >> 2);
     output[1] = binary_to_base64((input[0] & 0x03) << 4 | input[1] >> 4);
     output[2] = binary_to_base64((input[1] & 0x0F) << 2 | input[2] >> 6);
     output[3] = binary_to_base64( input[2] & 0x3F);

     input += 3;
     output += 4;
   }

   switch(input_length % 3) {
     case 0:
       output[0] = '\0';
       break;
     case 1:
       output[0] = binary_to_base64(                         input[0] >> 2);
       output[1] = binary_to_base64((input[0] & 0x03) << 4);
       output[2] = '=';
       output[3] = '=';
       output[4] = '\0';
       break;
     case 2:
       output[0] = binary_to_base64(                         input[0] >> 2);
       output[1] = binary_to_base64((input[0] & 0x03) << 4 | input[1] >> 4);
       output[2] = binary_to_base64((input[1] & 0x0F) << 2);
       output[3] = '=';
       output[4] = '\0';
       break;
   }

   return encode_base64_length(input_length);
 }

 String encode_base64(String input)
 {
   int encode_length = encode_base64_length(input);
   char output[encode_length];
   encode_base64((uint8_t*) input.c_str(), input.length(), (uint8_t*) output);
   return String(output).substring(0, encode_length);
 }

 unsigned int decode_base64(uint8_t input[], uint8_t output[]) {
   unsigned int output_length = decode_base64_length(input);

   // While there are still full sets of 24 bits...
   for(unsigned int i = 2; i < output_length; i += 3) {
     output[0] = base64_to_binary(input[0]) << 2 | base64_to_binary(input[1]) >> 4;
     output[1] = base64_to_binary(input[1]) << 4 | base64_to_binary(input[2]) >> 2;
     output[2] = base64_to_binary(input[2]) << 6 | base64_to_binary(input[3]);

     input += 4;
     output += 3;
   }

   switch(output_length % 3) {
     case 1:
       output[0] = base64_to_binary(input[0]) << 2 | base64_to_binary(input[1]) >> 4;
       break;
     case 2:
       output[0] = base64_to_binary(input[0]) << 2 | base64_to_binary(input[1]) >> 4;
       output[1] = base64_to_binary(input[1]) << 4 | base64_to_binary(input[2]) >> 2;
       break;
   }

   return output_length;
 }

 String decode_base64(String input)
 {
   int decode_length = decode_base64_length(input);
   char output[decode_length];
   decode_base64((uint8_t*) input.c_str(), (uint8_t*) output);
   return String(output).substring(0, decode_length);
 }
