package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
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
public abstract class AbstractSecurityHandler implements ISecurityHandler {
  

  private final String keystorePassword;
  private final String clientId;
  // credentials cache
  protected Token guestToken = null;
  
  //In memory credentials wallet by Home AAM id -> Client ID -> User ID -> Credentials
  protected Map<String, Map<String, Map<String, Certificate>>> credentialsWallet =
      new HashMap<>();
  
  //Associate tokens with credentials
  protected Map<String, Certificate> tokenCredentials = new HashMap<>();
  
  private boolean isOnline;
  
  
  
  /**
   * Creates a new instance of the Security Handler
   *
   * @param keystorePassword required to unlock the persisted keystore for this client
   * @param clientId         user defined identifier of this Security Handler
   * @param isOnline         if the security Handler has access to the Internet and SymbIoTe Core
   * @throws SecurityHandlerException on instantiation errors
   */
  public AbstractSecurityHandler(String keystorePassword,
                                 String clientId,
                                 boolean isOnline)
      throws SecurityHandlerException {
    // enabling support for elliptic curve certificates
    ECDSAHelper.enableECDSAProvider();
    
    // rest of the constructor code
    this.keystorePassword = keystorePassword;
    this.clientId = clientId;
    this.isOnline = isOnline;
    
    buildCredentialsWallet(isOnline);
  }
  
  
  public Certificate getHomeCertificate(String aamInstanceId, String user, String clientId) {
    Map<String, Map<String, Certificate>> aamClients = credentialsWallet.get(aamInstanceId);
    if (aamClients != null) {
      Map<String, Certificate> clientUsers = aamClients.get(clientId);
      if (clientUsers != null) {
    	return clientUsers.get(user);
      }
    }
    
    return null;
  }
  
  public Map<String, AAM> getAvailableAAMs(AAM homeAAM) throws SecurityHandlerException {
    AvailableAAMsCollection response = ClientFactory.getAAMClient(homeAAM.getAamAddress()).getAvailableAAMs();
    return response.getAvailableAAMs();
  }
  
  public String login(AAM homeAAMId, String user, String clientId) throws SecurityHandlerException {
    PrivateKey privateKey = getPrivateKey(homeAAMId.getAamInstanceId(), user, clientId);
    
    if (privateKey != null) {
      HomeCredentials credentials = new HomeCredentials(homeAAMId, user, clientId, null, privateKey);
      String homeToken = ClientFactory.getAAMClient(homeAAMId.getAamAddress()).getHomeToken(
          CryptoHelper.buildHomeTokenAcquisitionRequest(credentials));
      tokenCredentials.put(homeToken, getHomeCertificate(homeAAMId.getAamInstanceId(), user, clientId));
    } else {
      throw new SecurityHandlerException("Can't find certificate for client id " + clientId
                                             + " and user " + user);
    }
    
    return null;
    
  }
  
  public Map<AAM, String> login(List<AAM> foreignAAMs, String homeToken)
      throws SecurityHandlerException {
    
    Certificate certificate = tokenCredentials.get(homeToken);
    if (certificate != null) {
      
      String certificateStr = certificate.getCertificateString();
      return foreignAAMs.stream().collect(Collectors.toMap(aam -> aam, aam -> {
        return ClientFactory.getAAMClient(aam.getAamAddress()).getForeignToken(homeToken, certificateStr);
      }));
      
    } else {
      throw new SecurityHandlerException("Can't find credentials for token " + homeToken);
    }
    
  }
  
  public String loginAsGuest(AAM aam) {
    return ClientFactory.getAAMClient(aam.getAamAddress()).getGuestToken();
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
      
      request.setClientCSRinPEMFormat(CryptoHelper.buildCertificateSigningRequest(
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
    }
    
  }
  
  private void cacheCertificate(HomeCredentials credentials) {
    
    Map<String, Map<String, Certificate>> clients = credentialsWallet.get(credentials.homeAAM.getAamInstanceId());
    
    if (clients == null) {
      clients = new HashMap<>();
      credentialsWallet.put(credentials.homeAAM.getAamInstanceId(), clients);
    }
    
    Map<String, Certificate> users = clients.get(clientId);
    if (users == null) {
      users = new HashMap<>();
      clients.put(clientId, users);
    }
    

    users.put(credentials.username, credentials.certificate);
  }
  
  @Override
  public void clearCachedTokens() {
    tokenCredentials = new HashMap<>();
  }
  
  /**
   * Read all certificates in the keystore and populate the credentialsWallet object
   * @param isOnline
   * @throws SecurityHandlerException
   */
  private void buildCredentialsWallet(boolean isOnline) throws SecurityHandlerException {
  
  }
  
  // en el tag del keystore guardar codificado: amm_id|clientId|username|tipo de certificado, priv o cert
  private boolean saveCertificate(HomeCredentials credentials) {
    return true;
  }
  
  // Private keys are read from keystore and never cached
  private PrivateKey getPrivateKey(String aamId, String clientId, String userId) {
    return null;
  }
}
