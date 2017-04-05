/**

 Copyright (c) 2016, Interior Automation Ltd.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation and/or
    other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors may be
    used to endorse or promote products derived from this software without specific prior
    written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 **/

#ifndef ARDUINO_JWT_H
#define ARDUINO_JWT_H

#include <Arduino.h>



class ArduinoJWT {
private:
  String _psk;

public:
  ArduinoJWT(String psk);
  ArduinoJWT(char* psk);

  // Set a new psk for encoding and decoding JWTs
  void setPSK(String psk);
  void setPSK(char* psk);

  // Get the calculated length of a JWT
  int getJWTLength(String& payload);
  int getJWTLength(char* payload);
  // Get the length of the decoded payload from a JWT
  int getJWTPayloadLength(String& jwt);
  int getJWTPayloadLength(char* jwt);
  // Create a JSON Web Token
  String encodeJWT(String& payload);
  void encodeJWT(char* payload, char* jwt);
  // Decode a JWT and retreive the payload
  bool decodeJWT(String& jwt, String& payload);
  bool decodeJWT(char* jwt, char* payload, int payloadLength);
};

#endif
