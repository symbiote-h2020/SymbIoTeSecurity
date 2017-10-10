### Authorization and authentication
#### Challenge payload
All the claims marked with T means values of claims from AuthorizationToken for which challenge is made.
•	jti, random number,

•	iss, actor's unique identifier is sent,

•	sub contains the unique identifier of the token,

•	ipk is the public key of the actor.
 
•	hash contains a SHA256 hash of the token and timestamp

•	Issue (“iat”) and expiration date (“exp”) limit the validity of the challenge token.

•	hash claim contains a SHA256 hash of the authorization token compact form String concatenated with the challenge timestamp1

#### Service Response payload
#####Example:
An Application wants to demonstrate the token ownership through the Challenge-Response procedure. To do so, he has to generate a JWS message, signed using actor's private key complementary with its public key. From all of this components (data + JWS), text chain is generated and sent to a Service. 
Claims description:

•	hash claim contains a SHA256 hash of the timestamp2

•	timestamp claim contains the timestamp2

Example Challenge JWS compact token:
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Y2xpZW50aWQiLCJzdWIiOiJBdXRob3JpemF0aW9uVG9rZW5KVEkiLCJpcGsiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU3dThiZzVuT09zeFp2a2RtSytaY3Z4K2J5aTkzaVErbE1XSHNBY09hT0F3Ym1jU1UzbEtFWEt1M2dwL3ltaVhVaEl5RnV3MlBreGZlN1QxZTRIU21xQT09IiwiaGFzaCI6ImVjNTNkYmEwZjkzNzYyMzEwMzVjNWM1ZjFmNDIwM2UzNDgyNDcwOWUwOTkyZDU3NTZhYmY3N2VhNjc2ZWJkNjQiLCJpYXQiOjE1MDE1MDk3ODIsImV4cCI6MTUwMTUwOTg0Mn0.HjomIkzFXbTjokKDwGTgdHOsU19HdM3xXZFRoHqqIdY
```
 Full Challenge JSON:
```json
{
  "alg": "ES256",
  "typ": "JWT"
}
```
If token ownership is satisfied, Service sends back the Response Token.
Example Response JWS compact token:
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJoYXNoIjoiYWVkNTE3OTI4OTk4MjM4MDkzNDk3MzRkMDU4ZjdhYzIyODliZjE4OTU0NzEyMmIzMmMyMzBiZjAxMDAwYWExNyIsInRpbWVzdGFtcCI6MTUwNDc3MTMzNzAwMH0.2Oj6Dx4rzg5poB19z9opdEPquQvqg9l65HVnG_C-dU4
```
Full Response JSON:

```json
{
  "alg": "ES256",
  "typ": "JWT"
}
```

```
{
  "hash" : "aed51792899823809349734d058f7ac2289bf189547122b32c230bf01000aa17",
  "timestamp": 1504771337000
}
```
