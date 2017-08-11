package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Abstract implementation of the {@link ISecurityHandler} that all concrete implementations should
 * extend from.
 */
public class SecurityHandler implements ISecurityHandler {
  
  private static final Log logger = LogFactory.getLog(SecurityHandler.class);
  

  private final String keystorePath;
  private final String keystorePassword;
  
  //In memory credentials wallet by Home AAM id -> Client ID -> User ID -> Credentials
  private Map<String, BoundCredentials> credentialsWallet =
      new HashMap<>();
  
  //Associate tokens with credentials
  private Map<String, BoundCredentials> tokenCredentials = new HashMap<>();
  
  private boolean isOnline;
  
  
  
  /**
   * Creates a new instance of the Security Handler
   *
   * @param keystorePassword required to unlock the persisted keystore for this client
   * @param isOnline         if the security Handler has access to the Internet and SymbIoTe Core
   * @throws SecurityHandlerException on instantiation errors
   */
  public SecurityHandler(String keystorePath,
                         String keystorePassword,
                         boolean isOnline)
      throws SecurityHandlerException {
    // enabling support for elliptic curve certificates
    ECDSAHelper.enableECDSAProvider();
    
    // rest of the constructor code
    this.keystorePath = keystorePath;
    this.keystorePassword = keystorePassword;
    this.isOnline = isOnline;
  
    try {
      buildCredentialsWallet(isOnline);
    } catch (Exception e) {
      throw new SecurityHandlerException("Error generating credentials wallet", e);
    }
  }
  
  
  public Map<String, AAM> getAvailableAAMs(AAM homeAAM) throws SecurityHandlerException {
    AvailableAAMsCollection response = ClientFactory.getAAMClient(homeAAM.getAamAddress()).getAvailableAAMs();
    return response.getAvailableAAMs();
  }
  
  public Token login(AAM homeAAMId) throws SecurityHandlerException, ValidationException {
      BoundCredentials credentials = credentialsWallet.get(homeAAMId.getAamInstanceId());
    
    if (credentials != null && credentials.homeCredentials != null &&
            credentials.homeCredentials.privateKey != null) {
      String homeToken = ClientFactory.getAAMClient(homeAAMId.getAamAddress()).getHomeToken(
          CryptoHelper.buildHomeTokenAcquisitionRequest(credentials.homeCredentials));
        credentials.homeCredentials.homeToken = new Token(homeToken);
      tokenCredentials.put(homeToken, credentials);
        return credentials.homeCredentials.homeToken = new Token(homeToken);
    } else {
      throw new SecurityHandlerException("Can't find certificate for AAM " + homeAAMId.getAamInstanceId());
    }
  }
  
  public Map<AAM, Token> login(List<AAM> foreignAAMs, String homeToken)
      throws SecurityHandlerException {
  
    BoundCredentials credentials = tokenCredentials.get(homeToken);
    if (credentials != null && credentials.homeCredentials != null
            && credentials.homeCredentials.certificate != null) {
      
      String certificateStr = credentials.homeCredentials.certificate.getCertificateString();
      Map<AAM, Token> result = foreignAAMs.stream().collect(Collectors.toMap(aam -> aam, aam -> {
        try {
          return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getForeignToken(homeToken, certificateStr));
        } catch (ValidationException e) {
          logger.error("Invalid token returned for AAM " + aam.getAamInstanceId());
          return null;
        }
      }));
      
      credentials.foreignTokens = result;
      return result;
      
    } else {
      throw new SecurityHandlerException("Can't find credentials for token " + homeToken);
    }
    
  }
  
  public Token loginAsGuest(AAM aam) throws ValidationException {
    return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getGuestToken());
  }

    private static KeyStore getKeystore(String path, String password) throws
            KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (
                FileInputStream fIn = new FileInputStream(path)) {
            trustStore.load(fIn, password.toCharArray());
        }
        return trustStore;
    }

    public ValidationStatus validate(AAM validationAuthority, String token, Optional<Certificate> clientCertificate, Optional<Certificate> aamCertificate) {
    return ClientFactory.getAAMClient(validationAuthority.getAamAddress()).validate(token,
            clientCertificate.orElse(new Certificate()).getCertificateString());
    }

    private void cacheCertificate(HomeCredentials credentials) {

        BoundCredentials bound = new BoundCredentials(credentials.homeAAM);
        bound.homeCredentials = credentials;

        credentialsWallet.put(credentials.homeAAM.getAamInstanceId(), bound);
    }

    @Override
    public void clearCachedTokens() {
        tokenCredentials = new HashMap<>();
        credentialsWallet.values().forEach(credential -> {
            credential.foreignTokens = new HashMap<>();
            credential.homeCredentials.homeToken = null;
        });
  }
  
  public Certificate getCertificate(AAM homeAAM, String username, String password,
                                    String clientId)
      throws SecurityHandlerException {


      try {
      KeyPair pair = CryptoHelper.createKeyPair();

      CertificateRequest request = new CertificateRequest();
      request.setUsername(username);
      request.setPassword(password);
      request.setClientId(clientId);

      request.setClientCSRinPEMFormat(CryptoHelper.buildCertificateSigningRequestPEM(
          homeAAM.getCertificate().getX509(), username, clientId, pair));

          String certificateValue = ClientFactory.getAAMClient(homeAAM.getAamAddress())
                                    .getClientCertificate(request);

          Certificate certificate = new Certificate();
      certificate.setCertificateString(certificateValue);

          HomeCredentials credentials = new HomeCredentials(homeAAM, username, clientId, certificate,
                                                           pair.getPrivate());


          if (saveCertificate(credentials)) {
        cacheCertificate(credentials);
      } else {
        throw new SecurityHandlerException("Error saving certificate in keystore");
      }

          return certificate;

      } catch (CertificateException e) {
      throw new SecurityHandlerException("Error getting AAM certificate", e);
    } catch (IOException e) {
      throw new SecurityHandlerException("Error signing certificate request", e);
    } catch (NoSuchAlgorithmException e) {
      throw new SecurityHandlerException("Error generating key pair", e);
    } catch (NoSuchProviderException e) {
      throw new SecurityHandlerException("Error generating key pair", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new SecurityHandlerException("Error generating key pair", e);
      } catch (KeyStoreException e) {
          throw new SecurityHandlerException("Error saving certificate in keystore", e);
      } catch (InvalidArgumentsException e) {
          throw new SecurityHandlerException(e.getMessage(), e);
      }

  }
  
  private KeyStore getKeystore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    return getKeystore(keystorePath, keystorePassword);
  }
  
  /**
   * Read all certificates in the keystore and populate the credentialsWallet
   * @param isOnline
   * @throws SecurityHandlerException
   */
  private void buildCredentialsWallet(boolean isOnline) throws SecurityHandlerException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException {
    
    KeyStore trustStore = getKeystore();
  
    Enumeration<String> aliases = trustStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
  
      PrivateKey pvKey = (PrivateKey) trustStore.getKey(alias, keystorePassword.toCharArray());
      X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
      
      String subject = cert.getSubjectX500Principal().getName();
      if (subject.startsWith("CN=")) {
        String[] elements = subject.split("CN=")[1].split("@");
        if (elements.length > 2) {
          String user = elements[0];
          String client = elements[1];
          String aamId = elements[2];
  
          AAM aam = new AAM();
          aam.setAamInstanceId(aamId);
          
          BoundCredentials boundCredentials = new BoundCredentials(aam);
          
          Certificate certificate = new Certificate();
          certificate.setCertificateString(CryptoHelper.convertX509ToPEM(cert));
          
          boundCredentials.homeCredentials = new HomeCredentials(aam, user, client, certificate, pvKey);
          
          
          credentialsWallet.put(aamId, boundCredentials);
        }
      }
    }
  }

  private boolean saveCertificate(HomeCredentials credentials) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
 
	  KeyStore trustStore = getKeystore();
    
    String aliastag = credentials.homeAAM.getAamInstanceId();
  
    trustStore.setKeyEntry(aliastag, credentials.privateKey, keystorePassword.toCharArray(),
        new java.security.cert.Certificate[]{credentials.certificate.getX509()});
    
    FileOutputStream fOut = new FileOutputStream(keystorePath);
    trustStore.store(fOut, keystorePassword.toCharArray());
	  
    return true;
  }
  
}
