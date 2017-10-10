### Authorization Token acquisition
To acquire access to any resource, actor needs to acquire authorization token ([JSON Web Token](https://jwt.io/introduction/)).

#### Guest Token
Guest Token is a authorization token, for which no registration is required
[see [IFeignAAMClient](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/interfaces/IFeignAAMClient.java), getGuestToken()].
However, it can give access only to public resources. 

#### Home Token 
Home Token is a authorization token, for registered actors only. It can give access to public and private resources (depending on actors privileges).

To log in into a service and acquire Home Token, actor has to generate and send Login Request to the Local AAM in which he is registered. 
Login Request is a [JSON Web Token](https://jwt.io/introduction/), with right claims, containing JWS. In *iss*, actor's unique identifier is sent, *sub* contains one of the actor's client identifier. 
Issue (“iat”) and expiration date (“exp”) limit the validity of the token. Login Request can be created for registered actors with issued certificate in local AAM or for guest.

![Login Request structure](media/home-acquisition.png "Login request token format and content in symbIoTe.")

#### Structure of *sub* and *iss* claim
There are two kinds of *sub* claim, depending on for who Login Request is created. 

For ordinary user or PO:
```
ISS: username
SUB: clientId
```
For symbiote components acting on behalf of the CoreAAMOwner or PlatformOwner:
```
ISS: AAMOwnerUsername/PlatformOwnerUsername
SUB: componentId@PlatformId
```
where platformId is be **Symbiote_Core_AAM** for core components.

##### Structure of *sign* claim
For the sign generation, we use of ECDSA algorithm, by leveraging elliptic curve public keys 256-bits long 
(being 256 the recommended length for EC keys, equivalent to a security level of 128 bits).

Let T<sub>U</sub> be the token (excluding the sign field), H a generic hash function, and P<sub>V,Actor</sub> the private key of the actor that issues the token. 
Then, the sign is computed as:

 sign =  SIGN-ECDSA<sub>256</sub> (H(T<sub>U</sub>), P<sub>V,Actor</sub>)
 
An AAM that would like to verify the authenticity and integrity of the token T<sub>U</sub> needs to gather the public key 
of the actor, namely P<sub>B,Actor</sub> and verify that:

H(T<sub>U</sub>) = VERIFY-ECDSA<sub>256</sub> (H(T<sub>U</sub>), P<sub>B,Actor</sub>)

In case the equation is verified, the token is valid, i.e. it is authentic and integral.

##### Example

Actor wants to acquire Home Token for one of the registrated clients. To do so, he has to generate JWS message, modified JWT from his username, client id, actual data as issue_date and expiration_date (issue_date + 60s). All the information is signed, using actor's private key complementary with the public key for registrated client. From all of this components (data + JWS), text chain is generated and sent to AAM. 
Example login request JWS compact token:

```
eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0dXNlcm5hbWUiLCJzdWIiOiJ0ZXN0Y2xpZW50aWQiLCJpYXQiOjE1MDE1MDk3ODIsImV4cCI6MTUwMTUwOTg0Mn0.SGNpyl3zRA_ptRhA0lFH0o7-nhf3mpxE95ss37_jHYbCnwlRb4zDvVaYCj9DlpppU4U0y3vIPEqM44vV2UZ5Iw
```

Full JSON:

HEADER:
```json
{
    "alg": "ES256"
}
```
PAYLOAD:
```json
{
    "iss": "testusername",
    "sub": "testclientid",
    "iat": 1501509782,
    "exp": 1501509842
}
```
One can compare the above using: https://jwt.io/

##### Signature credentials
Actor's client Public Key (one that the actor stores in the AAM-bound certificate).
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7u8bg5nOOsxZvkdmK+Zcvx+byi93
iQ+lMWHsAcOaOAwbmcSU3lKEXKu3gp/ymiXUhIyFuw2Pkxfe7T1e4HSmqA==
-----END PUBLIC KEY-----
```
Actor's client Private Key - known  only to the actor
```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG4jKF3TUcXuKFeyZ0QucJDF6i9SB/i10lnK5pLBVdGqoAoGCCqGSM49
AwEHoUQDQgAE7u8bg5nOOsxZvkdmK+Zcvx+byi93iQ+lMWHsAcOaOAwbmcSU3lKE
XKu3gp/ymiXUhIyFuw2Pkxfe7T1e4HSmqA==
-----END EC PRIVATE KEY-----
```
AAM is converting that message to acquire actor's username and client_id, checks if "token" is valid, authentic and integral using public key from database. 
If everything is ok, AAM sends back Home Authorization Token.