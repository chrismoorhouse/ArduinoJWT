/*
Top Level Example / Unit Test
*/

#include "ArduinoJWT.h"

ArduinoJWT JWT((String) "secret");

String header = "{\"alg\": \"HS256\", \"typ\": \"JWT\"}";
String output = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Vo1KUsDkkzOw6DCXPJsZX-SOBMtWHUcCeHu13ydrYMw";

void setup(){
  Serial.begin(115200);
  Serial.println();

  String encode, decode, success;

  // Encode
  encode = JWT.encodeJWT(header);
  success = (output == encode ? "True" : "False");

  // Print results
  Serial.println("Encode Test");
  Serial.println("Input: " + header);
  Serial.println("Expected Output: " + output + ", length: " + output.length());
  Serial.println("Received Output: " + encode + ", length: " + encode.length());
  Serial.println("Success: " + success);
  Serial.println();

  // Decode
  decode = JWT.decodeJWT(encode);
  success = (header == decode ? "True" : "False");

  // Print results
  Serial.println("Decode Test");
  Serial.println("Input: " + encode);
  Serial.println("Expected Output: " + header + ", length: " + header.length());
  Serial.println("Received Output: " + decode + ", length: " + decode.length());
  Serial.println("Success: " + success);
  Serial.println();


}

void loop(){
  // Main code here
}
