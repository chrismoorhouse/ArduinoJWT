/*
Just a quick test verifying base64 works properly
*/

#include "base64.h"

#define HEADER_NUM 3

String header[HEADER_NUM] = {
  "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
  "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
  "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"
};

String output[HEADER_NUM] = {
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
};


void setup(){
  Serial.begin(115200);
  Serial.println();

  for (int i=0; i<HEADER_NUM; i++){
    String encode, decode, success;
    int exp_length;

    // Encode
    encode = encode_base64(header[i]);
    exp_length = encode_base64_length(header[i]);
    success = (output[i] == encode ? "True" : "False");

    // Print results
    Serial.println("Encode Test # " + String(i + 1));
    Serial.println("Input: " + header[i]);
    Serial.println("Expected Length: " + (String) exp_length);
    Serial.println("Expected Output: " + output[i] + ", length: " + output[i].length());
    Serial.println("Received Output: " + encode + ", length: " + encode.length());
    Serial.println("Success: " + success);
    Serial.println();

    // Decode
    decode = decode_base64(encode);
    exp_length = decode_base64_length(encode);
    success = (header[i] == decode ? "True" : "False");

    // Print results
    Serial.println("Decode Test # " + String(i + 1));
    Serial.println("Input: " + encode);
    Serial.println("Expected Length: " + (String) exp_length);
    Serial.println("Expected Output: " + header[i] + ", length: " + header[i].length());
    Serial.println("Received Output: " + decode + ", length: " + decode.length());
    Serial.println("Success: " + success);
    Serial.println();

  }

}

void loop(){
  // Main code here

}
