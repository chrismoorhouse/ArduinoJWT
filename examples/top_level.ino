/*
Top Level Example / Unit Test
*/

#include "ArduinoJWT.h"

ArduinoJWT JWT((char*) "secret");

String header = "{\"alg\": \"HS256\", \"typ\": \"JWT\"}";
String output = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Vo1KUsDkkzOw6DCXPJsZX-SOBMtWHUcCeHu13ydrYMw";

void setup(){
  String _output, success;

  Serial.begin(115200);
  Serial.println();

  // Compute
  _output = JWT.encodeJWT(header);
  success = (output == _output ? "True" : "False");

  // Print results
  Serial.println("Input: " + header);
  Serial.println("Expected Output: " + output);
  Serial.println("Received Output: " + _output);
  Serial.println("Success: " + success);
  Serial.println();

}

void loop(){
  // Main code here
}
