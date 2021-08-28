#include <ArduinoJWT.h>
#include <sha256.h>

// Secret code
ArduinoJWT jwt = ArduinoJWT("secret");

void setup() {
  Serial.begin(115200);

  // Convert JSON payload to verified JWT
  char input1[] = "{\"name\": \"John Doe\",\"email\": \"john.doe@example.com\",\"iat\": 1630182518}";
  int input1Len = jwt.getJWTLength(input1);
  char output1[input1Len];
  jwt.encodeJWT(input1, output1);
  Serial.println("\nEncoded JWT:");
  Serial.println(output1);

  // Convert verified JWT to JSON payload
  int output1Len = sizeof(output1);
  char input2[output1Len];
  strncpy(input2, output1, output1Len);
  int input2L = sizeof(input2);
  int output2Len = jwt.getJWTPayloadLength(input2);
  char output2[output2Len];
  jwt.decodeJWT(input2, output2, output2Len);
  Serial.println("\nDecoded Payload:");
  Serial.println(output2);
}

void loop() {
  // put your main code here, to run repeatedly:

}
