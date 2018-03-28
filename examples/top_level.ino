/*
Top Level Example
*/

#include "ArduinoJWT.h"

ArduinoJWT JWT((char *) "secret");

void setup(){
  Serial.begin(115200);

  Serial.println();
  Serial.println(JWT.encodeJWT(header));

}

void loop(){
  // Main code here
}
