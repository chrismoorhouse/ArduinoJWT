/*
Top Level Example / Unit Test
*/

#include "ArduinoJWT.h"
#include "ec_keys.h"

#define HEADER_NUM 3

String keys[HEADER_NUM] = {
  "secret",
  "",
  ""
};

String header[HEADER_NUM] = {
  "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
  "{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
  "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"
};

// Change intermediate results according to your keys
String output[HEADER_NUM] = {
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.WI0fJ1ubHHCltv6KjDpFq3hnqK4brOjAAezOWqtX5ME",
  "",
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.b_A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhbY1aeoW8BSSbXnKoSG4WQRXlgcKfp36nSYjZiywTFrcg"
};

ArduinoJWT JWT;


void setup(){
  Serial.begin(115200);
  Serial.println();

  for (int i=0; i<HEADER_NUM; i++) {
    String encode, decode, success;

    if (i == RS256){
      // RS256 is not supported yet!
      Serial.println("Skipping RS256 Test!\n");
      continue;
    }

    // Set keys
    switch(i) {
        case HS256:
          JWT.setHS256key(keys[i]);
          break;

        // case RS256:
        //   JWT.setRS256keys(keys[i]);
        //   break;

        case ES256:
          // JWT.setES256keys(keys[i]);
          JWT.setES256keys(ec_private, ec_public);
          break;
    }

    // Encode
    encode = JWT.encodeJWT(header[i], Algo(i));
    success = (output[i] == encode ? "True" : "False");

    // Print results
    Serial.println("Encode Test # " + String(i + 1));
    Serial.println("Input: " + header[i]);
    Serial.println("Expected Output: " + output[i] + ", length: " + output[i].length());
    Serial.println("Received Output: " + encode + ", length: " + encode.length());
    Serial.println("Success: " + success);
    Serial.println();

    // Decode
    decode = JWT.decodeJWT(encode, Algo(i));
    success = (header[i] == decode ? "True" : "False");

    // Print results
    Serial.println("Decode Test # " + String(i + 1));
    Serial.println("Input: " + encode);
    Serial.println("Expected Output: " + header[i] + ", length: " + header[i].length());
    Serial.println("Received Output: " + decode + ", length: " + decode.length());
    Serial.println("Success: " + success);
    Serial.println();
  }

}

void loop(){
  // Main code here
}
