package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
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
import java.security.cert.CertificateException;
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
  
  //In memory credentials wallet by Home AAM id -> Client ID -> User ID -> Credentials
  protected Map<String, BoundCredentials> credentialsWallet =
      new HashMap<>();
  
  //Associate tokens with credentials
  protected Map<String, BoundCredentials> tokenCredentials = new HashMap<>();
  
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
    
    buildCredentialsWallet(isOnline);
  }
  
  
  public Map<String, AAM> getAvailableAAMs(AAM homeAAM) throws SecurityHandlerException {
    AvailableAAMsCollection response = ClientFactory.getAAMClient(homeAAM.getAamAddress()).getAvailableAAMs();
    return response.getAvailableAAMs();
  }
  
  public Token login(AAM homeAAMId) throws SecurityHandlerException, ValidationException {
    BoundCredentials credentials =credentialsWallet.get(homeAAMId.getAamInstanceId());
    
    if (credentials != null && credentials.homeCredentials != null &&
            credentials.homeCredentials.privateKey != null) {
      String homeToken = ClientFactory.getAAMClient(homeAAMId.getAamAddress()).getHomeToken(
          CryptoHelper.buildHomeTokenAcquisitionRequest(credentials.homeCredentials));
      credentials.homeToken = new Token(homeToken);
      tokenCredentials.put(homeToken, credentials);
    } else {
      throw new SecurityHandlerException("Can't find certificate for AAM " + homeAAMId.getAamInstanceId());
    }
    
    return null;
    
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
  
  public ValidationStatus validate(AAM validationAuthority, String token, Optional<Certificate> certificate) {
    return ClientFactory.getAAMClient(validationAuthority.getAamAddress()).validate(token,
        certificate.orElse(new Certificate()).getCertificateString());
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
    }
  
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
      credential.homeToken = null;
    });
  }
  
  /**
   * Read all certificates in the keystore and populate the credentialsWallet
   * @param isOnline
   * @throws SecurityHandlerException
   */
  private void buildCredentialsWallet(boolean isOnline) throws SecurityHandlerException {
  
  }

  private boolean saveCertificate(HomeCredentials credentials) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
 
	  char[] password = keystorePassword.toCharArray();
    Certificate cer =  credentials.certificate;
    
    FileInputStream fIn = new FileInputStream(keystorePath);
    KeyStore trustStore = KeyStore.getInstance("JKS");
    trustStore.load(fIn, password);
    
    String aliastag = credentials.homeAAM.getAamInstanceId();
  
    trustStore.setCertificateEntry(aliastag, cer.getX509());
    
    FileOutputStream fOut = new FileOutputStream(keystorePath);
    trustStore.store(fOut, password);
	  
    return true;
  }
  
}
