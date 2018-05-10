[![Build Status](https://api.travis-ci.org/symbiote-h2020/SymbIoTeSecurity.svg?branch=staging)](https://api.travis-ci.org/symbiote-h2020/SymbIoTeSecurity)
[![](https://jitpack.io/v/symbiote-h2020/SymbIoTeSecurity.svg)](https://jitpack.io/#symbiote-h2020/SymbIoTeSecurity)
[![codecov.io](https://codecov.io/github/symbiote-h2020/SymbIoTeSecurity/branch/staging/graph/badge.svg)](https://codecov.io/github/symbiote-h2020/SymbIoTeSecurity)
### Table of Contents
* [SymbIoTe Security Overview](#symbiote-security-overview) 
* [Access to public resources](#access-to-public-resources) 
* [Access resources with restricted access](#access-resources-with-restricted-access) 
* [Offering resources with restricted access](#offering-resources-with-restricted-access) 
* [Credentials revocation ](#credentials-revocation) 

# SymbIoTe Security Overview
This repository contains SymbIoTe security layer interfaces, payloads, helper methods and a thin client named the SecurityHandler used throughout different components and different layers. It contains methods that allow the clients to acquire authorization credentials, service to evaluate the received credentials in terms of both authorizing operations and authenticating the clients and finally the clients to verify the authenticity of service they interact with.

For such we define 2 most important security payloads
 - Security Request - a set of standardized payloads authorizing actor in the system (JSON Web Tokens) with the confirmation, that those payloads belong to it,
 - Service Response - a payload produced by SymbIoTe components which proofs that the received business response was produced by a genuine component.

## Context
To read more about the project, please see documentation of:
 * [SymbioteCloud](https://github.com/symbiote-h2020/SymbioteCloud)
 * [SymbioteCore](https://github.com/symbiote-h2020/SymbioteCore)
 
In general, symbIoTe is a mediator, an intermediary connecting applications and IoT platforms. The basic functionality is that of a registry service which lists platforms, their resources and properties, while also providing a way to map between the platforms' different APIs.

## How to include this library in your code
The codes will be transiently available using SymbioteLibraries dependency. However, should one want to include it directly, then
[Jitpack](https://jitpack.io/) can be used to easily import SymbIoTe Security in your code. In Jitpack's website you can find guidelines about how to include repositories for different build automation systems. In the symbIoTe project which utilizes [gradle](https://gradle.org/), developers have to add the following in the *build.gradle*:

1. Add jitpack in your root build.gradle at the end of repositories:
```gradle
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
# Access to public resources
We briefly show how the clients can acquire GUEST credentials required to access public resources in SymbIoTe. First comes the tutorial using our reference Java codes and afterwards the generic part for developers that don't want to use our implementation.

## Java developers

1. The following snippet generates the security headers
```java
// creating REST client communicating with SymbIoTe Authorization Services 
// AAMServerAddress can be acquired from SymbIoTe web page
IAAMClient restClient = ClientFactory.getAAMClient(AAMServerAddress);

// acquiring Guest Token
String guestToken = restClient.getGuestToken();

// creating securityRequest using guest Token
SecurityRequest securityRequest = new SecurityRequest(guestToken);

// converting the prepared request into communication ready HTTP headers.
Map<String, String> securityHeaders = new HashMap<>();
securityHeaders = securityRequest.getSecurityRequestHeaderParams();
```
With these headers containing your GUEST token you can use SymbIoTe APIs to access public resources.
It can be also acquired in the following way, using end user Java client described [here](#end-user-security-handler):
```java
// Initializing application security handler
ISecurityHandler clientSH = ClientSecurityHandlerFactory.getSecurityHandler(
         coreAAMServerAddress,
         KEY_STORE_PATH,
         KEY_STORE_PASSWORD,
         clientId
);
// examples how to retrieve AAM instances
AAM coreAAM = clientSH.getCoreAAMInstance();
AAM platform1 = clientSH.getAvailableAAMs().get(platformId);

// Acquiring GUEST token from platform1
Token guestToken = clientSH.loginAsGuest(platform1);

// creating securityRequest using guest Token
SecurityRequest securityRequest = new SecurityRequest(guestToken);

// converting the prepared request into communication ready HTTP headers.
Map<String, String> securityHeaders = new HashMap<>();
securityHeaders = securityRequest.getSecurityRequestHeaderParams();
```

2. Then, after receiving the response from a SymbIoTe component, you should check if it came from component you are interested. To do that you can use the following snippet
```java 
 // trying to validate the service response
MutualAuthenticationHelper.isServiceResponseVerified(serviceResponse, restClient.getComponentCertificate(componentIdentifier, platformIdentifier));
``` 
where the componentIdentifier can be read from the table available [here](#component_table).

## Non java developers
1. To acquire a GUEST Token, send empty HTTP POST request on:
```
https://<coreInterfaceAdress>/get_guest_token
```
or
```
https://<platformInterworkingInterface>/paam/get_guest_token
```
depending which platform you want to acquire the GUEST token from. Please be aware that either of them has the same authorization power.
In return you will get empty response which header *x-auth-token* contains your GUEST token.

2. Create Security Request

To make use of your GUEST token you need to wrap it into our SecurityRequest. For standardized communication we deploy it into the following HTTP headers:
* current timestamp in miliseconds goes into header
  * x-auth-timestamp
* don't change just include
  * x-auth-size=1
* special JSON structure
  * under header x-auth-1
  * containing populated field:
    * "token":"HERE_COMES_THE_TOKEN_STRING",
  * and empty fields which you don't need to care about, just put the there:
    * "authenticationChallenge":"",
    * "clientCertificate":"",
    * "clientCertificateSigningAAMCertificate":"",
    * "foreignTokenIssuingAAMCertificate":""

**Example:**
 - x-auth-timestamp: 1519652051000
 - x-auth-size: 1
 - x-auth-1:
     ```java
     {
       "token":"eyJhbGciOiJFUzI1NiJ9.eyJ0dHlwIjoiR1VFU1QiLCJzdWIiOiJndWVzdCIsImlwayI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVBhZURDNElnT3VITlBmWCtURG5adXZuTHdUbHMwMERQb294aVZCTE8za3I0N0N3TXFYSm4yN3lpdFdZUkRRKzBmWG52MzFIbGJLbkxSWktqSmF5U3p3PT0iLCJpc3MiOiJTeW1iSW9UZV9Db3JlX0FBTSIsImV4cCI6MTUxMDU2Nzg2NywiaWF0IjoxNTEwNTY3MjY3LCJqdGkiOiI2MzI4NDUxMzAiLCJzcGsiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVsdlNwYVhDa2RFZ3lYM2xJeWQ1VCs2VFgyQ0hXMDluekNjL05aY2krcGEvdmtQSG5DeFZESkpLTkZwL1hQc0g2T1hvSTkxQXJFcUJ1SlJtd3k2dWZSdz09In0.zn7xjwUq89YSNptLTFCZSpb8n65n4o24HPOw2WPTJSglfaO8paW1O5vC3n9072ktm327kj44Kgs5qqMhRy22cA",
       "authenticationChallenge":"",
       "clientCertificate":"",
       "clientCertificateSigningAAMCertificate":"",
       "foreignTokenIssuingAAMCertificate":""
     } 
     ```

3. With such prepared headers you can access SymbIoTe resources offered publicly, e.g. execute search queries or send request to Resource Access Proxy.

4. After receiving a business response from a symbiote component, you should check if it came from component you are interested in. To do so, please see [Service Response payload](#service_response)

# Access resources with restricted access 
The sections below demonstrate the SymbioteSecurity in depth for parties interested in accessing resources with limited access.
In general, to access a resource with restricted access, SecurityRequest payload with homeToken issued for the users client needs to be sent. 
The whole path looks as follows:
1. user creates an account in the platform, in which he wants to access resources
2. <a name="access_priv_resources_2"></a> user, using credentials from the registration process, acquire a certificate(PKI) for his client
3. client acquire homeToken from it's home AAM
4. <a name="access_priv_resources_4"></a> client generates Security Request to authorize himself in the system
5. client gets access to the restricted resource (if he has rights to use it) using Security Request

Note that users credentials (username and password) are used in this process only during registration and acquisition of the certificates. They should not be saved on the clients device!  
## Java developers
This section provides the information about usage of SymbIoTe Security library in the java code. 
It requires from user its prior registration in the platform, in which he wants to access resources.

#### End-user Security Handler
Security handler class is a thin Java client providing methods allowing clients to acquire authorization and authentication credentials required to gain access to symbIoTe resource:
 - `Map<String, AAM> getAvailableAAMs()` - returns map of all currently available security entrypoints in symbiote (namely symbiote enabled platforms) obtained from the Core AAM as well as information about core components.
 - `Map<String, AAM> getAvailableAAMs(AAM aam)` - the same as above but obtained from the AAM (platform) specified in parameter. Information about components registered in this specified AAM and in core AAM is included.
 - `Token login(AAM aam)` - returns HOME token for your account in a given AAM (token is a digital object used as a container for security-related information. It serves for authorization purposes).
 - `Map<AAM, Token> login(List<AAM> foreignAAMs, String homeToken)` - allows you to acquire FOREIGN tokens from AAMs in which you don't have accounts using one of your home tokens.
 - `Token loginAsGuest(AAM aam)` - returns a GUEST token that allows access to only public resources in symbIoTe.
 - `ValidationStatus validate(AAM validationAuthority, String token,
                                  Optional<String> clientCertificate,
                                  Optional<String> clientCertificateSigningAAMCertificate,
                                  Optional<String> foreignTokenIssuingAAMCertificate)` 
                                  - validates your credentials in the specified AAM.
 - `Certificate getComponentCertificate(String componentIdentifier, String platformIdentifier)` - returns certificate of the specified component belonging to the given platform needed for components authentication operation.
 - `Certificate getCertificate(AAM homeAAM,
                                   String username,
                                   String password,
                                   String clientId)` - method used to acquire a certificate(PKI) for your client from the home AAM (AAM in which actor is registered). The private key matching the acquired certificate will be used to authenticate the client by signing requests to AAM and other symbiote components.
- `getAcquiredCredentials()` - returns all saved credentials bound with a particular AAM.
- `AAM getCoreAAMInstance()` - returns the Core AAM instance.
- `void clearCachedTokens()` - clears all acquired tokens from memory (credentialsWallet).

See [SecurityHandler.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/handler/SecurityHandler.java) 

At the beginning of an integration with SymbIoTe Security Layer as end-user you have to receive an implementation of [ISecurityHandler.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/handler/ISecurityHandler.java) using [SecurityHandlerFactory.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/ClientSecurityHandlerFactory.java).
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

To acquire access to any of the resources, steps from [2](#access_priv_resources_2) to [4](#access_priv_resources_4) can be achieved easily using SecurityHandler. The following instructions have to be done:
```java
// Initializing application security handler
ISecurityHandler clientSH = ClientSecurityHandlerFactory.getSecurityHandler(
         coreAAMServerAddress,
         KEY_STORE_PATH,
         KEY_STORE_PASSWORD,
         clientId
);
// examples how to retrieve AAM instances
AAM coreAAM = clientSH.getCoreAAMInstance();
AAM platform1 = clientSH.getAvailableAAMs().get(platformId);

// Acquiring application certificate, this operation needs the user password
Certificate clientCertificate = clientSH.getCertificate(platform1, username, password, clientId);

// Acquiring HOME token from platform1 AAM
Token token = clientSH.login(platform1);

// preparing the security request using the credentials the actor has from platform 1
Set<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<>();
// please note that from now on we don't need the password and only the the client certificate and matching private key.
authorizationCredentialsSet.add(new AuthorizationCredentials(token, platform1, clientSH.getAcquiredCredentials().get(platform1.getAamInstanceId()).homeCredentials));
SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(authorizationCredentialsSet, false);
```

Then after received a business response from a symbiote component we can check if it came from component we are interested in with the following operations:
```java
// trying to validate the service response
MutualAuthenticationHelper.isServiceResponseVerified(serviceResponse, clientSH.getComponentCertificate(componentIdentifier, platformIdentifier));
```
<a name="component_table"></a>
In order to identify the certificate of the component you communicate with, please use the following table:

| Component name | Component certificate key in the AAM collection |
| ------ | ------ |
| Core search | search |
| Core registry | registry |
| Registration handler | reghandler |
| ResourceAccessProxy | rap |
| CoreResourceMonitor | crm |
| CoreResourceAccessMonitor | cram |
| other might appear | ... |


#### SecurityRequest and API
The SecurityRequest (available here [SecurityRequest.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/SecurityRequest.java)) 
is a set of payloads authorizing actor in the system (JSON Web Tokens) with the confirmation, that those payloads belong to it. It is split into the following HTTP security headers for REST communication. We also offer convenience converters on how to consume the SecurityRequest on your business API and how to prepare one for attaching to a REST request.
```java
// timestamp header
public static final String SECURITY_CREDENTIALS_TIMESTAMP_HEADER = "x-auth-timestamp";
// SecurityCredentials set size header
public static final String SECURITY_CREDENTIALS_SIZE_HEADER = "x-auth-size";
// each SecurityCredentials entry header prefix, they are number 1..size
public static final String SECURITY_CREDENTIALS_HEADER_PREFIX = "x-auth-";
```
whereas the ServiceResponseJWS is in contrast just a String and should be transport in the following header:
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
## Non java developers
### <a name="client_certificate"></a>Acquiring client certificates needed to get authorization credentials
The following image depicts in general how to get a symbIoTe authentication certificate:
![Certificate acquisition procedure](media/acquire_user_cert.png)

0. Make sure you have an account in the platform you want to access resources (using Home credentials).
1. Generate a new keystore with your **ECDSA** keypair using **secp256r1** curve.
2. Using that keypair generate a CSR (signed using **SHA256withECDSA**) for your client with the following CN
   - for ordinary user client:
     - CN=username@clientId@platformId (or SymbIoTe_Core_AAM for a core user)
     - CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)(@)(([\w-])+)$ 
   - for your component
     - CN=componentId@platform_id
     - CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)$
   - for a platform AAM
     - CN=platformId
     - CSR's format in REGEX: ^(CN=)(([\w-])+)$
3. submit the CSR along with other credentials to your HOME AAM on the following REST endpoint, to receive your signed Certificate:
```
https://<coreInterfaceAdress>/sign_certificate_request
```
or
```
https://<platformInterworkingInterface>/paam/sign_certificate_request
```

CSR is located in body of the request, sent with POST method.

[CertificateRequest](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/docs/src/main/java/eu/h2020/symbiote/security/communication/payloads/CertificateRequest.java) example:

```
{
  "username" : "testApplicationUsername",
  "password" : "testApplicationPassword",
  "clientId" : "clientId",
  "clientCSRinPEMFormat" : "-----BEGIN CERTIFICATE REQUEST-----\r\nMIH4MIGfAgEAMD0xOzA5BgNVBAMMMnRlc3RBcHBsaWNhdGlvblVzZXJuYW1lQGNs\r\naWVudElkQFN5bWJJb1RlX0NvcmVfQUFNMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\r\nQgAE6hgbq/xGIGp9aRPuzHY1MPuxAA3dmhZ/RQRD/F7t+fhjUaOboWDIkmeAMfw6\r\nc9X+3JZVcJlklBvjWFM+tm96qaAAMAoGCCqGSM49BAMCA0gAMEUCICLGFyqGDt+u\r\nekgxkwpulG53JEMVoQ+OJp9dmf608a76AiEAved+JWfNmA6TBlwq/lllrVthE3rO\r\nru1m7ZyKHBdaoEQ=\r\n-----END CERTIFICATE REQUEST-----\r\n"
}
```

4. Home AAM verifies the request and response containing signed Certificate in body or error status should be received. Signed certificate is added to the HomeAAM's database for the user which send the request and given client's ID.
Response body example:
```
-----BEGIN CERTIFICATE-----
MIIBgjCCASigAwIBAgIBATAKBggqhkjOPQQDAjBJMQ0wCwYDVQQHEwR0ZXN0MQ0w
CwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MRowGAYDVQQDDBFTeW1iSW9UZV9D
b3JlX0FBTTAeFw0xNzEwMTIxMDQ5MDVaFw0xODEwMTIxMDQ5MDVaMD0xOzA5BgNV
BAMMMnRlc3RBcHBsaWNhdGlvblVzZXJuYW1lQGNsaWVudElkQFN5bWJJb1RlX0Nv
cmVfQUFNMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE22XrQOVU5dOYI7nWWE+M
3xNc//0kvpiT/tqOA3AL6Jj1ZZbsui8pQKKJzWjhOTgw0NHULbnqDO8eZ9F63b7D
MKMNMAswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNIADBFAiEA5MwiGcLYFj/9x/80
CR6oAmE3HVBkstwcAaYUsy3kUIECIAPGWPh++7In2oM/PirBFZoR8xKqufypo1lm
61fUd+FJ
-----END CERTIFICATE-----
```

5. User should store received signed Certificate in the Keystore with his private key.

From now the user can log in to his Home AAM and acquire home tokens from it.

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
Guest Token is an authorization token, for which no registration is required.
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
#### <a name="home_token"></a>Home Token 
Home Token is a authorization token, for registered actors only. It can give access to public and private resources (depending on actors privileges).

To log in into a service and acquire Home Token, actor has to generate and send Login Request to the AAM in which he is registered. 
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
For symbIoTe components acting on behalf of the Platform:
```
ISS: PlatformId
SUB: componentId
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

Actor wants to acquire Home Token for one of the registered clients. To do so, he has to generate JWS message, modified JWT from his username, client id, actual data as issue_date and expiration_date (issue_date + 60s). All the information is signed, using actor's private key complementary with the public key for registered client. From all of this components (data + JWS), text chain is generated and sent to AAM. 
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
### Authentication and Authorization payloads

All symbiote services that consume Authorization tokens need to verify the the client (sender) should be in possession of given token.
For that the client needs to generate a token ownership proof - challenge. All those need to be put in relevant headers in [SecurityRequest](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/master/src/main/java/eu/h2020/symbiote/security/communication/payloads/SecurityRequest.java). 
The SecurityRequest is split into the following HTTP security headers for communication.
 ```java
 // timestamp header
 public static final String SECURITY_CREDENTIALS_TIMESTAMP_HEADER = "x-auth-timestamp";
 // each SecurityCredentials entry header prefix, they are number 1..size
 public static final String SECURITY_CREDENTIALS_HEADER_PREFIX = "x-auth-"; 
// SecurityCredentials set size header
 public static final String SECURITY_CREDENTIALS_SIZE_HEADER = "x-auth-size";

 ```
The SECURITY_CREDENTIALS_HEADER_PREFIX of each token is created according the value of last header, which specifies the number of provided tokens.
Prefix contains JSON structure that consists of following [SecurityCredentials](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/documentation/src/main/java/eu/h2020/symbiote/security/communication/payloads/SecurityCredentials.java):
 - `String token` - a HOME or FOREIGN token string;
 - `String authenticationChallenge` - generated using MutualAuthenticationHelper or the procedure described below
 - `String clientCertificate` - (optional for offline validation) matching token SPK claim
 - `String clientCertificateSigningAAMCertificate` - (optional for offline validation) matching clientCertificate signature
 - `String foreignTokenIssuingAAMCertificate` - (optional for offline validation) matching @{@link Type#FOREIGN} ISS and IPK claims 

**Example:**
 - x-auth-timestamp: 1519723453000
 - x-auth-size: 1
 - x-auth-1:
```java
{
   "token":"eyJhbGciOiJFUzI1NiJ9.eyJ0dHlwIjoiSE9NRSIsInN1YiI6InJoIiwiaXBrIjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFN2VTYUlicWNRSnNpUWRmRXpPWkZuZlVQZWpTSkpDb1R4SSt2YWZiS1dyclZSUVNkS3cwdlYvUmRkZ3U1SXhWTnFkV0tsa3dpcldsTVpYTFJHcWZ3aHc9PSIsImlzcyI6InBsYXRmb3JtLTEiLCJleHAiOjE1MTk3MjM0NTUsImlhdCI6MTUxOTcyMzQ1MywianRpIjoiMTY0ODE2NzgxNiIsInNwayI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWVwK1VPTHFVbGRuamJwL0V4UGNpNHV3ZDk0bzRpczM0SXFCYmlhS2VmMXlPd2hUQ2wzcEw2Y1ErNXhRMFN5ajd2NEtscngvamRVUEhGN2dpQktUVnVBPT0ifQ.82rEpMSdLs3VFfsrKkS17wjtnP5A2dZm8J70CG-YNrp-GwvDeRSj1DJiR0qKYfu5oOm5-cTsqJm7UGVjZaorCQ",
   "authenticationChallenge":"eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiIzNzk3OTg3MjAiLCJzdWIiOiIxNjQ4MTY3ODE2IiwiaXNzIjoicmgiLCJpcGsiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVlcCtVT0xxVWxkbmpicC9FeFBjaTR1d2Q5NG80aXMzNElxQmJpYUtlZjF5T3doVENsM3BMNmNRKzV4UTBTeWo3djRLbHJ4L2pkVVBIRjdnaUJLVFZ1QT09IiwiaGFzaCI6IjNmNjkyMmQwMGQzMWY2NmFlOWE3ODQ1ZWIzNjRhZjVlN2UzODNmZDA2ODQxYTMzZGFlZTZmZTVlNDg5ZTI1MjMiLCJpYXQiOjE1MTk3MjM0NTMsImV4cCI6MTUxOTcyMzUxM30.PJpwjkL672KGYzipFqzNJeBzxRDL51p8zo0y70tM5wJWsluYVpjkQ6yQtt4jAiWJhSrtYmyHybE1MXbAdxkyBw",
   "clientCertificate":"",
   "clientCertificateSigningAAMCertificate":"",
   "foreignTokenIssuingAAMCertificate":""
} 
```
Such SecurityRequest can be used to get access to the proper resource. It is also used in Resource Access Proxy and in Search to execute search queries.  

As a response to all of ours SecurityRequests, ServiceResponse is received with business response from a symbiote component, thanks to which we can check if it came from component we are interested in.
The ServiceResponseJWS is in communication just a String and can be read from the following header
 ```java
 public static final SECURITY_RESPONSE_HEADER = "x-auth-response";
 ```

Striving for best interoperability, we also use the JWS as the challenge payload.

![Challenge payload structure](media/challenge-payload.PNG)

All the claims marked with T means values of claims from AuthorizationToken for which challenge is made.

* jti is the  token's identifier    
* iss is the actor's client identifier (SUB from the authorization token)    
* sub contains the JTI of the authorization token    
* ipk is the public key of the actor, spk from the authorization token   
* issue (“iat”) and expiration date (“exp”) limit the validity of the challenge token    
* hash claim contains a SHA256 hash of the authorization token compact form String concatenated with the challenge timestamp1     
* sign claim is the same as in the login request - uses the client's private key

#### <a name="service_response"></a>Service Response payload
The client can verify that the service response was genuine by checking that the service response contains a valid JWS token.
![Service response structure](media/service-response.png)

Claims description:   
* hash claim contains a SHA256 hash of the timestamp2    
* timestamp claim contains the timestamp2    
* sign claim is the same as in the login request - uses the service's private key   

The client can verify that the response was generated recently and is signed with the desired service private key by checking the tokens signature against the component's exposed certificate available in its platform AAM using a GET request.
```
https://<coreInterfaceAdress>/get_component_certificate/platform/SymbIoTe_Core_AAM/component/<componentID>
```
or
```
https://<platformInterworkingInterface>/paam/get_component_certificate/platform/<platformID>/component/<componentID>
```
The certificate is returned in the body in PEM format.

##### Example:
An Application wants to demonstrate the token ownership through the Challenge-Response procedure. To do so, he has to generate a JWS message, signed using actor's private key complementary with its public key. From all of this components (data + JWS), text chain is generated and sent to a Service. 


Example Challenge JWS compact token:
```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Y2xpZW50aWQiLCJzdWIiOiJBdXRob3JpemF0aW9uVG9rZW5KVEkiLCJpcGsiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU3dThiZzVuT09zeFp2a2RtSytaY3Z4K2J5aTkzaVErbE1XSHNBY09hT0F3Ym1jU1UzbEtFWEt1M2dwL3ltaVhVaEl5RnV3MlBreGZlN1QxZTRIU21xQT09IiwiaGFzaCI6ImVjNTNkYmEwZjkzNzYyMzEwMzVjNWM1ZjFmNDIwM2UzNDgyNDcwOWUwOTkyZDU3NTZhYmY3N2VhNjc2ZWJkNjQiLCJpYXQiOjE1MDE1MDk3ODIsImV4cCI6MTUwMTUwOTg0Mn0.HjomIkzFXbTjokKDwGTgdHOsU19HdM3xXZFRoHqqIdY
```
The foregoing token in compact JWS readable JSON format:
```json
{
  "alg": "ES256",
  "typ": "JWT"
}
{
  "iss": "testclientid",
  "sub": "AuthorizationTokenJTI",
  "ipk": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7u8bg5nOOsxZvkdmK+Zcvx+byi93iQ+lMWHsAcOaOAwbmcSU3lKEXKu3gp/ymiXUhIyFuw2Pkxfe7T1e4HSmqA==",
  "hash" : "ec53dba0f9376231035c5c5f1f4203e34824709e0992d5756abf77ea676ebd64",
  "iat": 1501509782,
  "exp": 1501509842
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

### Example REST scenario of accessing to private resources for non-java developers
0. Register user in relevant PAAM
1. Get client certificate

**Example:**
```java
-----BEGIN CERTIFICATE-----
MIIBgjCCASigAwIBAgIBATAKBggqhkjOPQQDAjBJMQ0wCwYDVQQHEwR0ZXN0MQ0w
CwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MRowGAYDVQQDDBFTeW1iSW9UZV9D
b3JlX0FBTTAeFw0xNzEwMTIxMDQ5MDVaFw0xODEwMTIxMDQ5MDVaMD0xOzA5BgNV
BAMMMnRlc3RBcHBsaWNhdGlvblVzZXJuYW1lQGNsaWVudElkQFN5bWJJb1RlX0Nv
cmVfQUFNMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE22XrQOVU5dOYI7nWWE+M
3xNc//0kvpiT/tqOA3AL6Jj1ZZbsui8pQKKJzWjhOTgw0NHULbnqDO8eZ9F63b7D
MKMNMAswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNIADBFAiEA5MwiGcLYFj/9x/80
CR6oAmE3HVBkstwcAaYUsy3kUIECIAPGWPh++7In2oM/PirBFZoR8xKqufypo1lm
61fUd+FJ
-----END CERTIFICATE-----
```
Please look [here](#client_certificate) how to get client certificate.

2. Acquire home token

**Example login request JWS compact token:**

```
eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0dXNlcm5hbWUiLCJzdWIiOiJ0ZXN0Y2xpZW50aWQiLCJpYXQiOjE1MDE1MDk3ODIsImV4cCI6MTUwMTUwOTg0Mn0.SGNpyl3zRA_ptRhA0lFH0o7-nhf3mpxE95ss37_jHYbCnwlRb4zDvVaYCj9DlpppU4U0y3vIPEqM44vV2UZ5Iw
```

Compact JWS readable JSON format:

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
 
[Here](#home_token) you can see how to acquire home token.


3. Create Security Request Headers
   
   To make use of your home token you need to wrap it into our SecurityRequest. For standardized communication we deploy it into the following HTTP headers:
   * x-auth-timestamp - current timestamp in miliseconds
   * x-auth-size=1 - don't change just include
   * x-auth-1 containing fields:
     * "token":"HERE_COMES_THE_TOKEN_STRING",
     * "authenticationChallenge":"",
     * "clientCertificate":"",
     * "clientCertificateSigningAAMCertificate":"",
     * "foreignTokenIssuingAAMCertificate":""
   
   **Example:**
   - x-auth-timestamp: 1519723453000
   - x-auth-size: 1
   - x-auth-1:
        ```java
        {
          "token":"eyJhbGciOiJFUzI1NiJ9.eyJ0dHlwIjoiSE9NRSIsInN1YiI6InJoIiwiaXBrIjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFN2VTYUlicWNRSnNpUWRmRXpPWkZuZlVQZWpTSkpDb1R4SSt2YWZiS1dyclZSUVNkS3cwdlYvUmRkZ3U1SXhWTnFkV0tsa3dpcldsTVpYTFJHcWZ3aHc9PSIsImlzcyI6InBsYXRmb3JtLTEiLCJleHAiOjE1MTk3MjM0NTUsImlhdCI6MTUxOTcyMzQ1MywianRpIjoiMTY0ODE2NzgxNiIsInNwayI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWVwK1VPTHFVbGRuamJwL0V4UGNpNHV3ZDk0bzRpczM0SXFCYmlhS2VmMXlPd2hUQ2wzcEw2Y1ErNXhRMFN5ajd2NEtscngvamRVUEhGN2dpQktUVnVBPT0ifQ.82rEpMSdLs3VFfsrKkS17wjtnP5A2dZm8J70CG-YNrp-GwvDeRSj1DJiR0qKYfu5oOm5-cTsqJm7UGVjZaorCQ",
          "authenticationChallenge":"eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiIzNzk3OTg3MjAiLCJzdWIiOiIxNjQ4MTY3ODE2IiwiaXNzIjoicmgiLCJpcGsiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVlcCtVT0xxVWxkbmpicC9FeFBjaTR1d2Q5NG80aXMzNElxQmJpYUtlZjF5T3doVENsM3BMNmNRKzV4UTBTeWo3djRLbHJ4L2pkVVBIRjdnaUJLVFZ1QT09IiwiaGFzaCI6IjNmNjkyMmQwMGQzMWY2NmFlOWE3ODQ1ZWIzNjRhZjVlN2UzODNmZDA2ODQxYTMzZGFlZTZmZTVlNDg5ZTI1MjMiLCJpYXQiOjE1MTk3MjM0NTMsImV4cCI6MTUxOTcyMzUxM30.PJpwjkL672KGYzipFqzNJeBzxRDL51p8zo0y70tM5wJWsluYVpjkQ6yQtt4jAiWJhSrtYmyHybE1MXbAdxkyBw",
          "clientCertificate":"",
          "clientCertificateSigningAAMCertificate":"",
          "foreignTokenIssuingAAMCertificate":""
        } 
        ```
   
4. With such prepared headers you can access SymbIoTe resources offered privately, e.g. execute search queries.
5. After receiving a business response from a symbiote component, you should check if it came from component you are interested in. To do so, please see [Service Response payload](#service_response)


# Offering resources with restricted access 
The sections below demonstrate the SymbioteSecurity in depth for parties interested in offering resources with limited access.

## Java developers
This section provides the information about usage of SymbIoTe Security library in the java code. 

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
     * @param componentOwnerUsername         AAMAdmin credentials 
     * @param componentOwnerPassword         AAMAdmin credentials
     * @return the component security handler ready to talk with Symbiote components
     * @throws SecurityHandlerException on creation error (e.g. problem with the wallet)
     */
ComponentSecurityHandler componentSecurityHandler = 
    ComponentSecurityHandlerFactory.getComponentSecurityHandler(
            coreAAMAddress, keystorePath, keystorePassword, clientId, localAAMAddress, 
            alwaysUseLocalAAMForValidation, componentOwnerUsername, componentOwnerPassword);
```

Component Security Handler provides following methods:
 - `Set<String> getSatisfiedPoliciesIdentifiers(Map<String, IAccessPolicy> accessPolicies,
                                                    SecurityRequest securityRequest)` - returns a set of identifiers of policies (e.g. resources identifiers) which are satisfied with the given SecurityRequest
 - `boolean isReceivedServiceResponseVerified(String serviceResponse,                                                  
                                                  String componentIdentifier,
                                                  String platformIdentifier)` - is used by a component to verify that the other components response was legitimate... e.g. to handle the service response encapsulated in a JWS. Returns true if the service is genuine.
 - `SecurityRequest generateSecurityRequestUsingLocalCredentials()` - is used by a component to generate the SecurityRequest needed to authorize operations in the Symbiote Environment to be attached to the business query
             so that the service can confirm that the client should posses provided tokens. Returns the required payload for client's authentication and authorization.
 - `String generateServiceResponse()` - returns the required payload that should be attached next to the components API business response so that the client can verify that the service is legitimate.  
 - `ISecurityHandler getSecurityHandler()` - returns Security Handler if the component owner wants to use it directly

To set up component SH, following instructions have to be done. Example for a platform registrationHandler
```java
IComponentSecurityHandler registrationHandlerCSH = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                coreAAMAddress,
                KEY_STORE_PATH,
                KEY_STORE_PASSWORD,
                "reghandler" + "@platfom1",
                localAAMAddress,
                false,
                componentOwnerUsername,
                componentOwnerPassword);

// building a service response that needs to be attached to each of your business responses
String regHandlerServiceResponse = rhCSH.generateServiceResponse();

// building a security request to authorize operation from the registration handler in other platforms' components (e.g. Core Registry)
SecurityRequest rhSecurityRequest = rhCSH.generateSecurityRequestUsingLocalCredentials();
```

To check validity of a response, if it came from component we are interested in (e.g. from the Core Registry), following operation have to be done: 
```java  
// trying to validate the service response
registrationHandlerCSH.isReceivedServiceResponseVerified(serviceResponse, "registry", "SymbIoTe_Core_AAM); 
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
                 .target(MyServiceFeignClient.class, url);
```
From now on, all methods call to jsonclient will generate REST requests with valid authentication headers and the responses will be validated as well for integrity, so in case of a challenge-response failure it will return a 400 error message.

### Attribute Based Access Control
The owner of a resource can establish a policy that describe using attributes, by whom and what operations can be performed on this object. 
If a subject has the attributes that satisfies the access control policy established by the resource owner, then the subject is authorized to perform the desidered operation on that object.
All attributes are stored in authorization tokens.
Authorization tokens are issued only by AAMs.

For the simplest IBAC (Identity-Based Access Control) implementation, the policies should look something like:
```json
AND:
    ISS: <PlatformInstanceIdentifier>
    SUB: <UserAuthorizedForThatResource1>
```
Access to the resource will be granted only to particular actor <UserAuthorizedForThatResource1>, who has token issued by specified platform <PlatformInstanceIdentifier>.
Another good example of the ABAC is an access policy for federated resource:
```json
AND:
    ISS: <PlatformInstanceIdentifier>
    ttyp: "FOREIGN"
    "SYMBIOTE_federation_{ordinal_number}" : "federationId"
```
Access to the resource will be granted to the actor, who has FOREIGN token issued by specified platform and contain attribute defining affiliation to the appropriate federation.

The package [eu/h2020/symbiote/security/accesspolicies](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies) 
offers a set of premade access policies that you can use out of the box (or always implement your own):
* [SingleLocalHomeTokenIdentityBasedTokenAccessPolicy.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/common/singletoken/SingleLocalHomeTokenIdentityBasedTokenAccessPolicy.java)
 – offers basically IdentityBasedAC - useful when you only want a particular user in your platform to access a resource
* [SingleLocalHomeTokenAccessPolicy.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/common/singletoken/SingleLocalHomeTokenAccessPolicy.java)
 – will offer access to the resource by any user that has an account in your platform.
* [ComponentHomeTokenAccessPolicy.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/common/singletoken/ComponentHomeTokenAccessPolicy.java)
 – will offer access to the resource by particular component from specified platform. Additional required claims can be specified.
* [SingleTokenAccessPolicy.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/common/singletoken/SingleTokenAccessPolicy.java) – most generic and simple implentation. You are free to set your required map of attributes that the user must possess. 
* [SingleFederatedTokenAccessPolicy.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/common/singletoken/SingleFederatedTokenAccessPolicy.java) - offer access to:
    * one of the federation members if his FOREIGN token contains the federation identifier claim
    * user which HOME token was issued by the home platform

To make it easier, above policies can be generated using special factory: [SingleTokenAccessPolicyFactory.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/common/SingleTokenAccessPolicyFactory.java).
To work, factory as a parameter needs object of [SingleTokenAccessPolicySpecifier.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/common/singletoken/SingleTokenAccessPolicySpecifier.java) class. 
It checks if the requirements for each ABAC was met and build proper policy (e.g. if issuer is defined in attributes map for SingleLocalHomeTokenAccessPolicy).

It's important to know, that creating your own AccessPolicy, it has to implement [IAccessPolicy.java](https://github.com/symbiote-h2020/SymbIoTeSecurity/tree/develop/src/main/java/eu/h2020/symbiote/security/accesspolicies/IAccessPolicy.java). 

#### ABAC example
To generate SingleLocalHomeTokenAccessPolicy, issuer claim has to be provided. 
```java
//generate required attributes map
Map<String, String> accessPolicyClaimsMap = new HashMap<>();
//only tokens with proper values of attributes 'name', 'age' and right issuer of the token can pass access policy
accessPolicyClaimsMap.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "name", "John");
accessPolicyClaimsMap.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "age", "18");
accessPolicyClaimsMap.put(Claims.ISSUER, deploymentId);

//generate SingleTokenAccessPolicySpecifier 
SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(
        SingleTokenAccessPolicySpecifier.SingleTokenAccessPolicyType.SLHTAP,
        accessPolicyClaimsMap
        );
//create map of active policies
Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
resourceAccessPolicyMap.put("resourceId", SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
```
Received Security Request must be checked against policies:
```java
Set<String> resp = componentSecurityHandler.getSatisfiedPoliciesIdentifiers(resourceAccessPolicyMap, securityRequest);
//returns set of identifiers of policies (e.g. resources identifiers) whose access policies are satisfied
```
Note, that all custom dynamic attributes (for ABAC only) in authorization tokens are prefixed according to SecurityConstants.java
```java
public static final String SYMBIOTE_ATTRIBUTES_PREFIX = "SYMBIOTE_";
```
For PUBLIC access to a resource, just use:
```java
new SingleTokenAccessPolicy(null);
```
This will be satisfied by any valid symbiote token.

# Credentials revocation 


In case of security breach, there may be need to revoke credentials such as certificates or tokens. 

## Java developers:
To revoke credentials, proper Revocation Request should be sent to the issuer AAM using AAMClient.
Revocation Request has following structure:
```java
private Credentials credentials = new Credentials();
private String homeTokenString = "";
private String foreignTokenString = "";
private String certificatePEMString = "";
private String certificateCommonName = "";
private CredentialType credentialType = CredentialType.NULL;
```
Appropriate fields have to be set using setters, depending on the kind of credentials we want to revoke.
To send the payload, AAMClient should be used:
```java
// payload should be sent to the issuer of the token/certificate
IAAMClient restClient = new AAMClient(issuerAAMOfCredentialsAddress);
// as response, boolean is received
boolean isRevoked = Boolean.parseBoolean(restClient.revokeCredentials(revocationRequest));
``` 
As the response, boolean value is received. 'true' stands for success, 'false' for failure of the revocation.
### Revocation of home token
To revoke home token and prevent any user from using it, following fields have to be set:
```java
RevocationRequest revocationRequest = new RevocationRequest();
revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
revocationRequest.setHomeTokenString(homeToken.toString());                 // homeToken for the revocation
revocationRequest.setCredentials(new Credentials(username, password));      // credentials of the token Owner
```
Payload should be sent to the issuer of this token.

### Revocation of foreign token
To revoke home token and prevent any user from using it, following fields have to be set:
```java
RevocationRequest revocationRequest = new RevocationRequest();
revocationRequest.setHomeTokenString(token.toString());           //homeToken based on which foreign token was issued
revocationRequest.setForeignTokenString(foreignToken.toString()); //foreign token to revoke
```
Payload should be sent to the issuer of the foreign token.

### Revocation of certificate
In case of security breach of our private key, certificate associated with it can be revoked to prevent impersonation. This applies to platforms and clients. It is possible to revoke certificate using its PEM or common name. Following fields have to be set: 
```java
RevocationRequest revocationRequest = new RevocationRequest();
revocationRequest.setCredentials(new Credentials(username, password)); //user or platformOwner credentials
revocationRequest.setCredentialType(RevocationRequest.CredentialType.USER);
revocationRequest.setCertificatePEMString(clientCertificate); //in case of revocation using PEM
// common name for client certs: username@clientId
// common name for platform certs: platformId
// revocationRequest.setCertificateCommonName(commonName); //in case of revocation using common Name
```
Payload should be sent to the issuer of the certificate (CoreAAM in case of platform certificate, proper platform in case of client one).
## Non java developers:
To revoke credentials, proper payload, Revocation Request, should be sent on following urls:
```
https://<coreInterfaceAdress>/revoke_credentials 
```
or
```
https://<platformInterworkingInterface>/paam/revoke_credentials
```
depending on the issuer of that credentials.
### Revocation Request
Revocation Request is a json payload carrying information needed to revoke compromised credentials. It contains fields such as:
```java
{
  "credentials" : {
    "username" : "",
    "password" : ""
  },
  "homeTokenString" : "",
  "foreignTokenString" : "",
  "certificatePEMString" : "",
  "certificateCommonName" : "",
  "credentialType" : "NULL"
}
```
Depending on the kind of credentials we want to revoke, proper fields should be filled.

### Revocation of home token
To revoke home token and prevent any user from using it, following fields have to be set:
```java
{
  "credentials" : {
    "username" : "tokenOwnerUsername", 
    "password" : "tokenOwnerPassword"
  },
  "homeTokenString" : "homeTokenString",        //home token to revoke
  "foreignTokenString" : "",
  "certificatePEMString" : "",
  "certificateCommonName" : "",
  "credentialType" : "USER"                     //DO NOT CHANGE THAT VALUE
}
```
Payload should be sent to the issuer of this token.

### Revocation of foreign token
To revoke home token and prevent any user from using it, following fields have to be set:
```java 
{
  "credentials" : {
    "username" : "tokenOwnerUsername",
    "password" : "tokenOwnerPassword"
  },
  "homeTokenString" : "homeTokenString",        //homeToken based on which foreign token was issued
  "foreignTokenString" : "foreignTokenString",  //foreign token for revocation
  "certificatePEMString" : "",
  "certificateCommonName" : "",
  "credentialType" : "NULL"                     //DO NOT CHANGE THAT VALUE
}
```
Payload should be sent to the issuer of the foreign token.

### Revocation of certificate
In case of security breach of our private key, certificate associated with it can be revoked to prevent impersonation. This applies to platforms and clients. It is possible to revoke certificate using its PEM or common name. Following fields have to be set: 
```java
{
  "credentials" : {
    "username" : "username",                    //user or platformOwner credentials
    "password" : "password"
  },
  "homeTokenString" : "",
  "foreignTokenString" : "",
  //certificate PEM strink to revoke
  "certificatePEMString" : "-----BEGIN CERTIFICATE-----\r\nMIIBgTCCASigAwIBAgIBATAKBggqhkjOPQQDAjBJMQ0wCwYDVQQHEwR0ZXN0MQ0w\r\nCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MRowGAYDVQQDDBFTeW1iSW9UZV9D\r\nb3JlX0FBTTAeFw0xODAyMjcxNDQ3MTNaFw0xOTAyMjcxNDQ3MTNaMD0xOzA5BgNV\r\nBAMMMnRlc3RBcHBsaWNhdGlvblVzZXJuYW1lQGNsaWVudElkQFN5bWJJb1RlX0Nv\r\ncmVfQUFNMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs8QnAVC9r4j11mik9dl9\r\nU5g1WbId/bZOSvyMMcskH+Gz/3McMEg0/yY6YkV/Zmr46oQ6xnHEHXipE3Rywigu\r\n2qMNMAswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNHADBEAiBWNmuWEUgLHRZ6YpHn\r\n5UlbPvWVn0y9k4RlKNFTDPpSKAIgWfJL34k28sG5+RKEZEXn8xsrMcS9LQYVLzVD\r\nHBdYUz8=\r\n-----END CERTIFICATE-----\r\n",
  //certificate common name to revoke (instead of PEM)
  "certificateCommonName" : "",
  "credentialType" : "USER"                     //DO NOT CHANGE THAT VALUE
}
```
Common name structure:
```java
username@clientId - for client certificates to revoke
platformId - for platform certificate
```
Sending payload with certificate commonName AND PEM will result in taking into consideration only commonName.
  
Payload should be sent to the issuer of the certificate (CoreAAM in case of platform certificate, proper platform in case of client one).
