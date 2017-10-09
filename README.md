[![Build Status](https://api.travis-ci.org/symbiote-h2020/SymbIoTeSecurity.svg?branch=staging)](https://api.travis-ci.org/symbiote-h2020/SymbIoTeSecurity)
[![](https://jitpack.io/v/symbiote-h2020/SymbIoTeSecurity.svg)](https://jitpack.io/#symbiote-h2020/SymbIoTeSecurity)
[![codecov.io](https://codecov.io/github/symbiote-h2020/SymbIoTeSecurity/branch/staging/graph/badge.svg)](https://codecov.io/github/symbiote-h2020/SymbIoTeSecurity)
# SymbIoTe Security
This repository contains SymbIoTe security layer interfaces, payloads, helper methods and a thin client named the SecurityHandler used throughout different components and different layers.

## How to include them in your code
The codes will be transiently available using SymbioteLibraries dependency. However, should one want to include it directly, then
[Jitpack](https://jitpack.io/) can be used to easily import SymbIoTe Security in your code. In Jitpack's website you can find guidelines about how to include repositories for different build automation systems. In the symbIoTe project which utilizes [gradle](https://gradle.org/), developers have to add the following in the *build.gradle*:

1. Add jitpack in your root build.gradle at the end of repositories:
```
allprojects {
	repositories {
		...
		maven { url 'https://jitpack.io' }
	}
}
```
2. Add the dependency:
```
compile('com.github.symbiote-h2020:SymbIoTeSecurity:develop-SNAPSHOT')
```
As you notice above, during development (i.e. feature and develop branches of component repositories) the ***develop*** branch of the SymbIoTeSecurity needs to be used, in order to make sure that the latest version is always retrieved. In the official releases (i.e. master branches of Component repositories), this dependecy will be changed to:

```
compile('com.github.symbiote-h2020:SymbIoTeSecurity:{tag}')
```
by the **SymbIoTe Security Team**.

Challenge-Response
==================

The *Challenge-Response procedure* is designed to verify the
component/application that is using a token is really the entity for
which this token has been issued by the AAM. The procedure leverages
public key cryptography: the owner of the token is in possession of a
private key associated to a public key stored into the token; therefore,
it executes some cryptographic operations by using such a private key;
then the security willing to verify the authenticity of the
application/component performs opposite operation through the public
key. In symbIoTe, a special challenge-response mechanism is designed,
which is conformed to the REST paradigm.

Proposed REST solution:
=======================

The following is result of CNIT & PSNC cooperation to achieve token
ownership proof - 'challenge-response' for end clients.

Prerequisites
-------------

-   Client wants to get access to a resource(Res 1), from Platform
    (Plat 1)

-   Each component in symbIoTe is in possession of its certificate and
    the corresponding private key

-   The user has n devices. For each device, it retrieves a private key,
    a certificate and valid tokens. From this moment on, the user-device
    pair is simply referred to as “client”.

Notation
--------

-   PV is the private key of the client

-   PK is the public key of the client

-   T*~i~* represents the homeToken issued by the *i-th* Platform AAM to
    the considered user. The token stores in the SPK field the public
    key of the user. When the user is registering to the platform, he
    obtains a certificate in order to demonstrate the authenticity of
    its public key.

-   H is a generic hash function

-   E() represents a cryptographic operation executed through a public
    key of the entity that will receive the message (used for the
    Signature Verification)

-   S() is a signature vector that contains the signatures made on the
    hash of correspondent token and a timestamp.

-   S~PV,i~ is the signature made with the *i-th* private key associated
    with the correspondent subject public key

-   **T**=\[T~1~,T~2~,...,T~n~\] is the tokens set owned by the client

Scenario
--------

The challenge and response mechanism involves the following steps:

a\) It is assumed that the client already retrieved the set of tokens

-   For each *i-th token, the client computes* S~i~=\[S~PV,A,i~(H(T~i~
    || *timestamp~1~*))\]

b\) The client sends a request to the remote entity, which contains:

-   The business request

-   The security request that contains:

    -   Set of SecurityCredentials each contains:

        -   A token, i.e. T~1~...T~n~

        -   An implicit challenge calculated as: **S**= S~PV,1~(H(Token~1~ || *timestamp~1~*)) || S~PV,2~(H(Token~2~|| *timestamp~1~*)) ... || ... S~PV,n~(H(Token~n~ ||*timestamp~1~*))

        -   *Optional Certificates
            (*clientCertificate, clientCertificateSigningAAMCertificate, foreignTokenIssuingAAMCertificate)

    -   The timestamp: *timestamp~1~*

c\) The remote entity performs the following operations:

-   for each *i* in \[1…n\]

    -   extract PK~A,i~ from T~i~

    -   *h*=E~PK,A,i~(S~i~)

    -   *hˈ=H*(T~i~ || *timestamp*~1~)

    - if (*h*=*hˈ & ((timestamp~NOW~* - *timestamp~1~*)&lt;    quantity))
    accept

    - end if

-   end

d\) The remote entity sends an answer as: BusinessReponse || ServiceResponseJWS

The ServiceResponseJWS contains: S~PV,P~(*H(timestamp2*) ||*timestamp~2~*)

e\) The client:

-   Verifies the signature: E~PK,P~(*timestamp~2~*), extracts *h*=H(*timestamp~2~*) from the signed payload.

-   Calculates *h'*=H(*timestamp~2~*), checks whether *h=h'* and the freshness of response.

Note that timestamps are used to guarantee the freshness of requests and responses.

Anyway in the sequence diagrams, this means that the request becomes
composite and contains (i.e.search params) request, token and challenge
(i.e. request foreign token with core token + challenge) and the
interaction "token(s) validation through challenge-response" contains
only the response.

When the application requests a foreign token, this last will contain
the subject public key as the first public key extract from the token
list during the challenge and response.

Benefits
--------

-   we utilize existing in Symbiote PKI

-   we encapsulate the stateful challenge-response into stateless
    blocking REST calls

Challenges:
-----------

-   requires each component to

    -   posses a certificate and private Key

    -   offer the certificate using an agreed AP

Challenge payload proposition
-----------------------------

For challenge procedure, the following JWS is proposed:


**Figure 1:** Challenge token format and content in symbIoTe.

All the claims marked with T means values of claims from Authorization Token,
for which challenge is made.

-   *jti*, random number,

-   *iss*, actor's unique identifier is sent,

-   *sub*, contains the unique identifier of the token,

-   *ipk* is the public key of the actor. 

-   *hash* contains a SHA256 hash of the *token* and *timestamp*

-   Issue (“*iat*”) and expiration date (“*exp*”) limit the validity of
    the challenge token.

-   *hash* claim contains a SHA256 hash of the authorization token
    compact form String concatenated with the challenge *timestamp~1~*

As for the challenge signature:

Let T~U~ be the token (excluding the sign field), H a generic hash
function, and P~V,Actor~ the private key of the actor  that issues the
token, matching *ipk*. Then, the sign is computed as:

sign = SIGN-ECDSA256 (H(TU), PV,Actor)

An AAM that would like to verify the authenticity and integrity of the
token T~U~ needs to gather the public key of the actor, namely
P~B,Actor~ and verify that:

H(TU) = VERIFY-ECDSA256 (H(TU), PB,Actor)

In case the equation is verified, the token is valid, i.e. it is
authentic, integral and proves that actor can posses this token.

Service Response payload proposition
------------------------------------

For response procedure, the following JWS is proposed:


**Figure 2:** Response token format and content in symbIoTe.

Claims description:

-   *hash* claim contains a SHA256 hash of the *timestamp~2~*

-   *timestamp* claim contains the *timestamp~2~*

Let T~U~ be the token (excluding the sign field), H a generic hash
function, and P~V,Service~ the private key of the service that issues
the token, matching *spk*. Then, the sign is computed as:

sign = SIGN-ECDSA256 (H(TU), PV,Service)

An Actor that would like to verify the authenticity and integrity of the
token T~U~ needs to gather the public key of the service, namely
P~B,Service~ and verify that:

H(TU) = VERIFY-ECDSA256 (H(TU), PB,Service)

Example:
--------

An Application wants to demonstrate the token ownership through the
Challenge-Response procedure. To do so, he has to generate a JWS
message, signed using actor's private key complementary with its public
key. From all of this components (data + JWS), text chain is generated
and sent to a Service.

Example Challenge JWS compact token:

eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Y2xpZW50aWQiLCJzdWIiOiJBdXRob3JpemF0aW9uVG9rZW5KVEkiLCJpcGsiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU3dThiZzVuT09zeFp2a2RtSytaY3Z4K2J5aTkzaVErbE1XSHNBY09hT0F3Ym1jU1UzbEtFWEt1M2dwL3ltaVhVaEl5RnV3MlBreGZlN1QxZTRIU21xQT09IiwiaGFzaCI6ImVjNTNkYmEwZjkzNzYyMzEwMzVjNWM1ZjFmNDIwM2UzNDgyNDcwOWUwOTkyZDU3NTZhYmY3N2VhNjc2ZWJkNjQiLCJpYXQiOjE1MDE1MDk3ODIsImV4cCI6MTUwMTUwOTg0Mn0.HjomIkzFXbTjokKDwGTgdHOsU19HdM3xXZFRoHqqIdY

 

Full Challenge JSON:
```json
{

"alg": "ES256",

"typ": "JWT"

}

{

"iss": "testclientid",

"sub": "AuthorizationTokenJTI",

"ipk":
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7u8bg5nOOsxZvkdmK+Zcvx+byi93iQ+lMWHsAcOaOAwbmcSU3lKEXKu3gp/ymiXUhIyFuw2Pkxfe7T1e4HSmqA==",

"hash" :
"ec53dba0f9376231035c5c5f1f4203e34824709e0992d5756abf77ea676ebd64",

"iat": 1501509782,

"exp": 1501509842

}
```

If token ownership is satisfied, Service sends back the Response Token.

Example Response JWS compact token:

eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJoYXNoIjoiYWVkNTE3OTI4OTk4MjM4MDkzNDk3MzRkMDU4ZjdhYzIyODliZjE4OTU0NzEyMmIzMmMyMzBiZjAxMDAwYWExNyIsInRpbWVzdGFtcCI6MTUwNDc3MTMzNzAwMH0.2Oj6Dx4rzg5poB19z9opdEPquQvqg9l65HVnG\_C-dU4

Full Response JSON:
```json
{

"alg": "ES256",

"typ": "JWT"

}

{

"hash" :
"aed51792899823809349734d058f7ac2289bf189547122b32c230bf01000aa17",

"timestamp": 1504771337000

}
```

Signature credentials
---------------------

Actor's client Public Key (one that the actor stores in the AAM-bound
certificate).

-----BEGIN PUBLIC KEY-----

MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7u8bg5nOOsxZvkdmK+Zcvx+byi93

iQ+lMWHsAcOaOAwbmcSU3lKEXKu3gp/ymiXUhIyFuw2Pkxfe7T1e4HSmqA==

-----END PUBLIC KEY-----

Actor's client Private Key - known  only to the actor

-----BEGIN EC PRIVATE KEY-----

MHcCAQEEIG4jKF3TUcXuKFeyZ0QucJDF6i9SB/i10lnK5pLBVdGqoAoGCCqGSM49

AwEHoUQDQgAE7u8bg5nOOsxZvkdmK+Zcvx+byi93iQ+lMWHsAcOaOAwbmcSU3lKE

XKu3gp/ymiXUhIyFuw2Pkxfe7T1e4HSmqA==

-----END EC PRIVATE KEY-----

Communication/implementation details
------------------------------------

The SecurityRequest is available
here [*SecurityRequest.java*](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/SecurityRequest.java)
and can be split into the following HTTP security headers for
communication.
```java
// timestamp header

public static final String SECURITY\_CREDENTIALS\_TIMESTAMP\_HEADER = "x-auth-timestamp";

// SecurityCredentials set size header

public static final String SECURITY\_CREDENTIALS\_SIZE\_HEADER = "x-auth-size";

// each SecurityCredentials entry header prefix, they are number 1..size

public static final String SECURITY\_CREDENTIALS\_HEADER\_PREFIX = "x-auth-";
```
whereas the ServiceResponseJWS is in communication just a String and
should be transport in the following header
```java
public static final SECURITY\_RESPONSE\_HEADER = "x-auth-response";
```
The headers are available in
the [*SecurityConstants.java*](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/SecurityConstants.java)

References
----------

\[1\] - ISO/IEC 9798-2, ISO/IEC 9798-3, ISO/IEC 9798-4 -
URL:[*https://www.iso.org/home.html*](https://www.iso.org/home.html)

\[2\] - Bradley, John, Nat Sakimura, and Michael Jones. "*JSON web
signature (JWS).*" (2015) -
URL: [*https://tools.ietf.org/html/rfc7515*](https://tools.ietf.org/html/rfc7515) 
