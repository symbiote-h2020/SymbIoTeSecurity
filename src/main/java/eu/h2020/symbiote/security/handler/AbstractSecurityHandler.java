package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.AAMClient;
import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
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
  
  // client configuration
  private final AAM coreAAM;
  private final String keystorePassword;
  private final String clientId;
  // credentials cache
  protected Token guestToken = null;
  
  //In memory credentials wallet by Home AAM id -> Client ID -> User ID -> Credentials
  protected Map<String, Map<String, Map<String, BoundCredentials>>> credentialsWallet =
      new HashMap<>();
  
  //Associate tokens with credentials
  protected Map<String, HomeCredentials> tokenCredentials = new HashMap<>();
  
  private boolean isOnline;
  
  private AAMClient aamClient;
  
  
  /**
   * Creates a new instance of the Security Handler
   *
   * @param coreAAM          from where the Security Handler can resolve the Symbiote se
   * @param keystorePassword required to unlock the persisted keystore for this client
   * @param clientId         user defined identifier of this Security Handler
   * @param isOnline         if the security Handler has access to the Internet and SymbIoTe Core
   * @throws SecurityHandlerException on instantiation errors
   */
  public AbstractSecurityHandler(AAM coreAAM,
                                 String keystorePassword,
                                 String clientId,
                                 boolean isOnline)
      throws SecurityHandlerException {
    // enabling support for elliptic curve certificates
    ECDSAHelper.enableECDSAProvider();
    
    // rest of the constructor code
    this.coreAAM = coreAAM;
    this.keystorePassword = keystorePassword;
    this.clientId = clientId;
    this.isOnline = isOnline;
    
    aamClient = ClientFactory.getAAMClient(coreAAM.getAamAddress());
    
    buildCredentialsWallet(isOnline);
  }
  
  
  public HomeCredentials getHomeCredentials(String aamInstanceId, String user, String clientId) {
    Map<String, Map<String, BoundCredentials>> aamClients = credentialsWallet.get(aamInstanceId);
    if (aamClients != null) {
      Map<String, BoundCredentials> clientUsers = aamClients.get(clientId);
      if (clientUsers != null) {
        BoundCredentials credentials = clientUsers.get(user);
        if (credentials != null) {
          return credentials.homeCredentials;
        }
      }
    }
    
    return null;
  }
  
  public Map<String, AAM> getAvailableAAMs() throws SecurityHandlerException {
    AvailableAAMsCollection response = aamClient.getAvailableAAMs();
    return response.getAvailableAAMs();
  }
  
  public String login(AAM homeAAMId, String user, String clientId) throws SecurityHandlerException {
    HomeCredentials credentials = getHomeCredentials(homeAAMId.getAamInstanceId(), user, clientId);
    
    if (credentials.privateKey != null) {
      String homeToken = ClientFactory.getAAMClient(homeAAMId.getAamAddress()).getHomeToken(
          CryptoHelper.buildHomeTokenAcquisitionRequest(credentials));
      tokenCredentials.put(homeToken, credentials);
    } else {
      throw new SecurityHandlerException("Can't find certificate for client id " + clientId
                                             + " and user " + user);
    }
    
    return null;
    
  }
  
  public Map<AAM, String> login(List<AAM> foreignAAMs, String homeToken)
      throws SecurityHandlerException {
    
    HomeCredentials credentials = tokenCredentials.get(homeToken);
    if (credentials != null && credentials.certificate != null) {
      
      String certificate = credentials.certificate.getCertificateString();
      return foreignAAMs.stream().collect(Collectors.toMap(aam -> aam, aam -> {
        return ClientFactory.getAAMClient(aam.getAamAddress()).getForeignToken(homeToken, certificate);
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
  
  private boolean saveCertificate(KeyPair pair, Certificate certificate, AAM aam, String username, String clientId) {
    return true;
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
      
      
      saveCertificate(pair, certificate, homeAAM, username, clientId);
      cacheCertificate(homeAAM, clientId, username, certificate, pair.getPrivate());
      
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
  
  private void cacheCertificate(AAM homeAAM, String clientId, String username,
                                Certificate certificate, PrivateKey aPrivate) {
    
    Map<String, Map<String, BoundCredentials>> clients = credentialsWallet.get(homeAAM.getAamInstanceId());
    
    if (clients == null) {
      clients = new HashMap<>();
      credentialsWallet.put(homeAAM.getAamInstanceId(), clients);
    }
    
    Map<String, BoundCredentials> users = clients.get(clientId);
    if (users == null) {
      users = new HashMap<>();
      clients.put(clientId, users);
    }
    
    BoundCredentials newCredentials = new BoundCredentials(homeAAM);
    newCredentials.homeCredentials = new HomeCredentials(homeAAM, username, clientId, certificate, aPrivate);
    users.put(username, newCredentials);
  }
  
  private void buildCredentialsWallet(boolean isOnline) throws SecurityHandlerException {
  
  }
  
  @Override
  public void clearCachedTokens() {
    tokenCredentials = new HashMap<>();
  }
}
