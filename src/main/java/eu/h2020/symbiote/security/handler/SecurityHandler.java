package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Abstract implementation of the {@link ISecurityHandler} that all concrete implementations should
 * extend from.
 */
public class SecurityHandler implements ISecurityHandler {
  
  private static final Log logger = LogFactory.getLog(SecurityHandler.class);
  
  
  private final String keystorePath;
  private final String keystorePassword;
  private final String homeAAMAddress;
  
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
                         boolean isOnline,
                         String homeAAMAddress)
      throws SecurityHandlerException {
    // enabling support for elliptic curve certificates
    ECDSAHelper.enableECDSAProvider();
    
    // rest of the constructor code
    this.keystorePath = keystorePath;
    this.keystorePassword = keystorePassword;
    this.isOnline = isOnline;
    this.homeAAMAddress = homeAAMAddress;
    
    try {
      buildCredentialsWallet(isOnline);
    } catch (Exception e) {
      throw new SecurityHandlerException("Error generating credentials wallet", e);
    }
  }
  
  
  public Map<String, AAM> getAvailableAAMs(AAM homeAAM) throws SecurityHandlerException {
    AvailableAAMsCollection response = ClientFactory.getAAMClient(homeAAM.getAamAddress())
                                           .getAvailableAAMs();
    return response.getAvailableAAMs();
  }
  
  public Token login(AAM homeAAMId) throws SecurityHandlerException, ValidationException {
    BoundCredentials credentials = credentialsWallet.get(homeAAMId.getAamInstanceId());
    
    if (credentials != null && credentials.homeCredentials != null &&
            credentials.homeCredentials.privateKey != null) {
      try {
        String homeToken = ClientFactory.getAAMClient(homeAAMId.getAamAddress()).getHomeToken(
            CryptoHelper.buildHomeTokenAcquisitionRequest(credentials.homeCredentials));
        credentials.homeCredentials.homeToken = new Token(homeToken);
        tokenCredentials.put(homeToken, credentials);
        return credentials.homeCredentials.homeToken = new Token(homeToken);
      } catch (WrongCredentialsException e) {
        throw new SecurityHandlerException("Wrong credentials provided for log in", e);
      } catch (JWTCreationException e) {
        throw new SecurityHandlerException("Error creating log in token", e);
      } catch (MalformedJWTException e) {
        throw new SecurityHandlerException("Malformed token sent", e);
      }
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
          return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getForeignToken(homeToken,
              Optional.ofNullable(certificateStr),
              Optional.ofNullable(credentials.homeCredentials.homeAAM.getCertificate().getCertificateString())));
        } catch (ValidationException e) {
          logger.error("Invalid token returned for AAM " + aam.getAamInstanceId(), e);
          return null;
        } catch (JWTCreationException e) {
          logger.error("Error creating log in token", e);
          return null;
        }
      }));
      
      credentials.foreignTokens = result;
      return result;
      
    } else {
      throw new SecurityHandlerException("Can't find credentials for token " + homeToken);
    }
    
  }
  
  public Token loginAsGuest(AAM aam) throws ValidationException, SecurityHandlerException {
    try {
      return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getGuestToken());
    } catch (JWTCreationException e) {
      throw new SecurityHandlerException("Error creating log in token", e);
    }
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
  
  public ValidationStatus validate(AAM validationAuthority, String token) {
    
    //Check if it's a home token
    final BoundCredentials[] tokenOwner = {tokenCredentials.get(token)};
    final AAM[] issuingAAM = {null};
    if (tokenOwner[0] == null) {
      // It might be a foreing token. We'll have to iterate
      tokenCredentials.values().stream().filter(credentials -> {
        Map.Entry<AAM, Token> found = credentials.foreignTokens.entrySet().stream()
                        .filter(entry -> entry.getValue().equals(token)).findFirst().orElse(null);
        if (found != null) {
          tokenOwner[0] = credentials;
          issuingAAM[0] = found.getKey();
          return true;
        } else {
          return false;
        }
      }).findFirst().orElse(null);
    } else {
      issuingAAM[0] = tokenOwner[0].homeCredentials.homeAAM;
    }
    
    String clientCertificate = (tokenOwner[0] != null)?
                                   tokenOwner[0].homeCredentials.certificate.getCertificateString():
                                   null;
    String clientSigningCertificate = (tokenOwner[0] != null)?
                                          tokenOwner[0].homeCredentials.homeAAM.getCertificate().getCertificateString()
                                          :null;
    String foreingTokenCertificate = (issuingAAM[0] != null)?
                                         issuingAAM[0].getCertificate().getCertificateString()
                                         :null;
  
  
    return ClientFactory.getAAMClient(validationAuthority.getAamAddress()).validate(token,
        Optional.ofNullable(clientCertificate),
        Optional.ofNullable(clientSigningCertificate),
        Optional.ofNullable(foreingTokenCertificate));
  }
  
  private void cacheCertificate(HomeCredentials credentials) {
    
    BoundCredentials bound = new BoundCredentials(credentials);
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
    } catch (WrongCredentialsException e) {
      throw new SecurityHandlerException(e.getMessage(), e);
    } catch (ValidationException e) {
      throw new SecurityHandlerException(e.getMessage(), e);
    } catch (NotExistingUserException e) {
      throw new SecurityHandlerException(e.getMessage(), e);
    }
    
  }
  
  private KeyStore getKeystore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    return getKeystore(keystorePath, keystorePassword);
  }
  
  /**
   * Read all certificates in the keystore and populate the credentialsWallet
   */
  private void buildCredentialsWallet(boolean isOnline) throws SecurityHandlerException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException {
    
    KeyStore trustStore = getKeystore();
    
    AAM homeAAM = new AAM();
    homeAAM.setAamAddress(homeAAMAddress);
    
    Map<String, AAM> aamList = getAvailableAAMs(homeAAM);
    
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
          
          AAM aam = aamList.get(aamId);
          
          if (aam != null) {
            Certificate certificate = new Certificate();
            certificate.setCertificateString(CryptoHelper.convertX509ToPEM(cert));
  
            BoundCredentials boundCredentials =
                new BoundCredentials(new HomeCredentials(aam, user, client, certificate, pvKey));
  
            credentialsWallet.put(aamId, boundCredentials);
          }
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