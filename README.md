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

## Instructions for java developers
#### End-user Security Handler

Security handler provides methods that allow retrieving AAMs (`getAvailableAAMs`), component certificates (`getComponentCertificate`), logging into AAMs (`login`) etc. See [SecurityHandler.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/handler/SecurityHandler.java) 

At the beginning of an integration with Sybiote Security Layer as end-user you have to receive an implementation of [ISecurityHandler.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/handler/ISecurityHandler.java) using [SecurityHandlerFactory.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/ClientSecurityHandlerFactory.java).
```java
/**
     * Creates an end-user security handler
     *
     * @param coreAAMAddress   Symbiote Core AAM address which is available 
     *                         on the symbiote security webpage
     * @param keystorePath     where the keystore will be stored
     * @param keystorePassword needed to access security credentials
     * @return the security handler ready to talk with Symbiote Security Layer
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
SecurityHandler securityHandler = ClientSecurityHandlerFactory.getSecurityHandler(
        coreAAMAddress, keystorePath, keystorePassword, userId);
```


In order to find the certificate of the component you communicate with, please use the following table:

| Component name | Component certificate key in the AAM collection |
| ------ | ------ |
| Core search | search |
| Core registry | registry |
| Registration handler | reghandler |
| RAP | rap |
| CRM | crm |
| CRAM | cram |

#### Component Security Handler
If you want to manage components, create ComponentSecurityHandler object with  [ComponentSecurityHandlerFactory](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/handler/ComponentSecurityHandler.java) class.
```java
/**
     * Creates an end-user component security handler
     *
     * @param coreAAMAddress                 Symbiote Core AAM address which is available 
     *                                       on the symbiote security webpage
     * @param keystorePath                   where the keystore will be stored
     * @param keystorePassword               needed to access security credentials
     * @param clientId                       name of the component in the form of "componentId@platformId"
     * @param localAAMAddress                when using only local AAM for SecurityRequest validation
     * @param alwaysUseLocalAAMForValidation when wanting to use local AAM for SecurityRequest validation
     * @param componentOwnerUsername         AAMAdmin credentials for core components 
     *                                       and platform owner credentials for platform components
     * @param componentOwnerPassword         AAMAdmin credentials for core components 
     *                                       and platform owner credentials for platform components
     * @return the component security handler ready to talk with Symbiote components
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
ComponentSecurityHandler componentSecurityHandler = 
    ComponentSecurityHandlerFactory.getComponentSecurityHandler(
            coreAAMAddress, keystorePath, keystorePassword, clientId, localAAMAddress, 
            alwaysUseLocalAAMForValidation, componentOwnerUsername, componentOwnerPassword);
```

#### SecurityRequest and API
The SecurityRequest (available here [SecurityRequest.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/SecurityRequest.java)) is split into the following HTTP security headers for REST communication. We also offer convenience converters on how to consume the SecurityRequest on your business API and how to prepare one for attaching to a REST request.
```java
// timestamp header
public static final String SECURITY_CREDENTIALS_TIMESTAMP_HEADER = "x-auth-timestamp";
// SecurityCredentials set size header
public static final String SECURITY_CREDENTIALS_SIZE_HEADER = "x-auth-size";
// each SecurityCredentials entry header prefix, they are number 1..size
public static final String SECURITY_CREDENTIALS_HEADER_PREFIX = "x-auth-";
```
whereas the ServiceResponseJWS is in communication just a String and should be transport in the following header
```java
public static final SECURITY_RESPONSE_HEADER = "x-auth-response";
```
The headers are available in the [SecurityConstants.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/SecurityConstants.java)

#### SecurityRequest and Guest token
The reference Java code to create the SecurityRequest with a GUEST token is provided in [SecurityRequest.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/SecurityRequest.java) constructor
```java
public SecurityRequest(String guestToken) {
    this.timestamp = ZonedDateTime.now().toInstant().toEpochMilli();
    this.securityCredentials = new HashSet<>();
    securityCredentials.add(new SecurityCredentials(guestToken));
}
```

#### Proxy client for access to AAM Services
In addition to the [IComponentSecurityHandler](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/handler/IComponentSecurityHandler.java) that was released, there's an utility class for REST clients using Feign. In case you are using it, it is created a client that will manage automatically the authentication headers and validate the server response (with respect to security). This class is [SymbioteAuthorizationClient](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/SymbioteAuthorizationClient.java).

So let's say that you have a Feign client named MyServiceFeignClient. Normally you would instantiate it like:

```java
Feign.builder().decoder(new JacksonDecoder())
                 .encoder(new JacksonEncoder())
                 .target(MyServiceFeignClient.class, url);
```

So now, if you want it to manage the security headers automatically, all you have to do is:


  1. Get an instance of the IComponentSecurityHandler:
   ```java

IComponentSecurityHandler secHandler = ComponentSecurityHandlerFactory
                                           .getComponentSecurityHandler(
                                               coreAAMAddress, keystorePath, keystorePassword,
                                               clientId, localAAMAddress, false,
                                               username, password );
```
  2. Create an instance of the [SymbioteAuthorizationClient](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/SymbioteAuthorizationClient.java) 
  passing the Security Handler instance and the target service (serviceComponentIdentifier of the service this client is used to communicate with and servicePlatformIdentifier to which the service belongs ([CORE_AAM_INSTANCE_ID](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/SecurityConstants.java#L20)) for Symbiote core components). So for example, the Registration Handler wanting to communicate with the Registry will pass `registry` in the first parameter and [CORE_AAM_INSTANCE_ID](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/SecurityConstants.java#L20) for the latter. This will allow the Security Handler to get the correct certificate to validate responses.
   ```java
Client client = new SymbioteAuthorizationClient(
    secHandler, serviceComponentIdentifier,servicePlatformIdentifier, new Client.Default(null, null));
```

And now you can pass it on your Feign client creation:
```java
MyServiceFeignClient jsonclient = Feign.builder()
                 .decoder(new JacksonDecoder())
                 .encoder(new JacksonEncoder())
                 .client(client)
                 .target(InterworkingInterfaceService.class, url);
```
From now on, all methods call to jsonclient will generate REST requests with valid authentication headers and the responses will be validated as well for integrity, so in case of a challenge-response failure it will return a 400 error message.



## Instructions for non java developers
###Certificates
How to get them
CSR
### Authorization Token acquisition
To acquire access to any resource, actor needs to acquire authorization credentials containing tokens ([JSON Web Token](https://jwt.io/introduction/)).

Actor needs to know **coreInterfaceAdress**. 
In case of acquiring tokens from other platform, their **platformInterworkingInterfaces** 
can be accessed, sending GET request on:
```
https://<coreInterfaceAdress>/get_available_aams
```
In return, response with json containing [AvailableAAMsCollection](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/AvailableAAMsCollection.java) should be received.

#### Guest Token
Guest Token is a authorization token, for which no registration is required.
However, it can give access only to public resources. 

To acquire such token, empty HTTP POST request has to be sent on:
```
https://<coreInterfaceAdress>/get_guest_token
```
or
```
https://<platformInterworkingInterface>/paam/get_guest_token
```
depending from which platform we want to acquire Guest Token.
In return, headers with *x-auth-token* containing Guest Token should be received.
#### Home Token 
Home Token is a authorization token, for registered actors only. It can give access to public and private resources (depending on actors privileges).

To log in into a service and acquire Home Token, actor has to generate and send Login Request to the Local AAM in which he is registered. 
Login Request is a [JSON Web Token](https://jwt.io/introduction/), with right claims, wrapped into JWS. In *iss*, actor's unique identifier is sent, *sub* contains one of the actor's client identifier. 
Issue (“iat”) and expiration date (“exp”) limit the validity of the token. Login Request can be created for registered actors with issued certificate in local AAM or for guest.

![Login Request structure](media/home-acquisition.png "Login request token format and content in symbIoTe.")

To acquire such token, HTTP POST request with proper headers has to be sent. 
Required request should look like this:
 ```
 x-auth-token: {token}
 ```
 where {token} is Login Request.
 Request should be send on:
```
https://<coreInterfaceAdress>/get_home_token
```
or
```
https://<platformInterworkingInterface>/paam/get_home_token
```
depending from which platform we want to acquire Home Token.
In return, headers with *x-auth-token* containing Home Token should be received.

#### Structure of *sub* and *iss* claim
There are two kinds of *sub* claim, depending on for who Login Request is created. 

For ordinary user or Platform Owner:
```
ISS: username
SUB: clientId
```
For symbiote components acting on behalf of the CoreAAMOwner or PlatformOwner [Note: R3 version, will be changed in R3.1]:
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
###Authentication and Authorization payloads
Challenge
Payloads