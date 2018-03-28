/*
Just a quick test verifying base64 works properly
*/

#include "../lib/base64.h"

#define HEADER_NUM 3

String header[HEADER_NUM] = {
  "{\"alg\": \"HS256\", \"typ\": \"JWT\"}",
  "{\"alg\": \"RS256\", \"typ\": \"JWT\"}",
  "{\"alg\": \"ES256\", \"typ\": \"JWT\"}"
};

String output[HEADER_NUM] = {
  "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9",
  "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9",
  "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9"
};


void setup(){
  Serial.begin(115200);
  Serial.println();

  for (int i=0; i<HEADER_NUM; i++){
    String _output, success;
    char b64_header[encode_base64_length(header[i].length())];

    // Compute
    encode_base64((unsigned char*) header[i].c_str(), header[i].length(), (unsigned char*) b64_header);
    _output = String(b64_header);
    success = (output[i] == _output ? "True" : "False");

    // Print results
    Serial.println("Test # " + String(i + 1));
    Serial.println("Input: " + header[i]);
    Serial.println("Expected Output: " + output[i]);
    Serial.println("Received Output: " + _output);
    Serial.println("Success: " + success);
    Serial.println();

  }

}

void loop(){
  // Main code here

}
