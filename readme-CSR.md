### Certificate acquisition
Main steps to make a certificate chain are:

1. Generate a keystore for Symbiote Core (Root CA) with certificate and private key.
2. Export Symbiote Core certificate (Root CA self-signed certificate).
3. The Platform (let's suppose a generic Platform (i.e. OpenIoT)) generates a key pair for itself.
4. The Platform does a CSR, submit it to the Root CA (Symbiote Core) that issues a certificate for Platform.
5. The Application (leaf, no CA) generates a key pair for itself.
6. Application does a CSR, submit it to Intermediate CA (OpenIoT Platform in this example) that issues a certificate for Application.
7. Now, if you want to check that certificates are chained, just import them on your machine and open the application certificate file to view certificate path.

#### Core AAM certificate

You need to create a JavaKeystore containing a certificate:

•	self-signed

•	with CA property enabled

•	with the following encryption params

•	SIGNATURE_ALGORITHM=SHA256withECDSA

•	CURVE_NAME=secp256r1

•	KEY_PAIR_GEN_ALGORITHM=ECDSA

•	with the CN value set according to AAMConstants.java field AAM_CORE_AAM_INSTANCE_ID value

•	with the certificate entry name "symbiote_core_aam"

This keystore will be used to self-initiliaze the AAM codes as Core AAM.

#### SSL certificate

To secure communication between the clients and your platform instance you need an SSL certificate(s) for your Core AAM and for your CoreInterface. Should they be deployed on the same host, the certificate can be reused in both components.

##### How to issue the certificate

Issue using e.g. [letsencrypt](https://letsencrypt.org/)
A certificate can be obtained using the [certbot shell tool](https://certbot.eff.org/) only for resolvable domain name.

Instructions for the Ubuntu (Debian) machine are the following: 

Install certbot:
```  
$ sudo apt-get install software-properties-common
$ sudo add-apt-repository ppa:certbot/certbot
$ sudo apt-get update
$ sudo apt-get install certbot python-certbot-apache
```
Obtain the certificate by executing 
```
$ certbot --apache certonly
```
     
Apache port (80 by default) should be accessible from outside on your firewall.
Select option Standalone (option 2) and enter your domain name.

Upon successful execution navigate to the location: 

```
/etc/letsencrypt/live/<domain_name>/ 
```
where you can find your certificate and private key (5 files in total, cert.pem  chain.pem  fullchain.pem  privkey.pem  README).

##### How to create a Java Keystore with the issued SSL certificate, required for Core AAM deployment

Create a Java Keystore containing the certificate. Use the KeyStore Explorer application to create [JavaKeystore](http://keystore-explorer.org/downloads.html):

1. (optionally) Inspect obtained files using Examine --> Examine File

2. Create a new Keystore --> PKCS #12

3. Tools --> Import Key Pair --> PKCS #8

4. Deselect Encrypted Private Key

5. Browse and set your private key (privkey.pem)

6. Browse and set your certificate (fullchain.pem)

7. Import --> enter alias for the certificate for this keystore
Enter password

8. File --> Save --> enter previously set password  --> <filename>.p12

Filename will be used as configuration parameter of the Core AAM component.
```
 server.ssl.key-store=classpath:<filename>.p12
```
#### Configuring the CoreAAM resources

Once one has done previous actions, you need to fix the file `src/main/resources/bootstrap.properties` manually for each deployment using the template below or comments from the file itself.

Example bootstrap.properties:
```
spring.cloud.config.enabled=true
spring.application.name=AuthenticationAuthorizationManager
logging.file=logs/AuthenticationAuthorizationManager.log
# security agreed constants
aam.security.KEY_PAIR_GEN_ALGORITHM=ECDSA
aam.security.CURVE_NAME=secp256r1
aam.security.SIGNATURE_ALGORITHM=SHA256withECDSA
  
# username and password of the AAM module (of your choice)
aam.deployment.owner.username=TODO
aam.deployment.owner.password=TODO
# name of the CAAM JavaKeyStore file you need to put in your src/main/resources directory
aam.security.KEY_STORE_FILE_NAME=TODO.p12
# name of the certificate entry in the Keystore
aam.security.KEY_STORE_ALIAS=symbiote_core_aam
# symbiote keystore password
aam.security.KEY_STORE_PASSWORD=TODO
# symbiote certificate private key password
aam.security.PV_KEY_PASSWORD=TODO
#JWT validity time in milliseconds - how long the tokens issued to your users (apps) are valid... think maybe of an hour, day, week?
aam.deployment.token.validityMillis=TODO
# HTTPS only
# name of the keystore containing the letsencrypt (or other) certificate and key pair for your AAM host's SSL, you need to put it also in your src/main/resources directory
server.ssl.key-store=classpath:TODO.p12
# SSL keystore password
server.ssl.key-store-password=TODO
# SSL certificate private key password
server.ssl.key-password=TODO
# http to https redirect
security.require-ssl=true
```

You also need to copy to the `src/main/resources/` directory:

•	JavaKeyStore file containing the self-signed Core AAM cert+key that you have generated
•	the keystore generated for your SSL certificate


In order to acquire relevant certificates using directly the AAM endpoint the actor (user/platform owner) needs to provide Certificate Request. 
It consists of credentials of the actor (username and password), client identifier and a Certificate Signing Request with the following specifics:

1.  
    Actor: common (either ordinary user (app) or platform owner) 

    AAM type: Core and Platform 
    
    Input format (CSR): CN=username@clientId@platformId (or SymbIoTe_Core_AAM for core user) 
    
    CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)(@)(([\w-])+)$ 
    
    Result: User client's certificate for acquiring HOME tokens 
    
2.
    Actor: Core AAM Admin 
    
    AAM type: Core 
        
    Input format (CSR): CN=componentId@SymbIoTe_Core_AAM 
        
    CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)$
        
    Result: Core components' certificate
    
3.
    Actor: Platform Owner
    
    AAM type: Core 
        
    Input format (CSR): CN=platformId
        
    CSR's format in REGEX: ^(CN=)(([\w-])+)$
        
    Result: Platform AAM's certificate
    
4.
    Actor: PO for R3, and for R3.1 Platform AAM Admin
        
    AAM type: Core 
           
    Input format (CSR): CN=componentId@platformId
            
    CSR's format in REGEX: ^(CN=)(([\w-])+)(@)(([\w-])+)$
            
    Result: Platform components' certificate
    
   
The User generates a CSR with a CN matching the aforementioned scheme that matches the Home AAM certificate data,
then sends a request for a certificate to the Home AAM (e.g. for the core through the Administration module).


The SignCertificateRequest is located in body of request which is sent with POST method on address:
```
https://<coreInterfaceAdress>/AAM_SIGN_CERTIFICATE_REQUEST
```


Home AAM verifies the request and signs the certificate that was requested in the CSR; newly signed certificate is written in Home AAM's database for that particular user and its client_id.
Generated by Home AAM and delivered to the client, it returns either a valid certificate or an error message. From now on the User can log in to his Home AAM and acquire home tokens from it.
    
    
    