package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.BoundCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.NotExistingUserException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.commons.exceptions.custom.WrongCredentialsException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.File;
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
  
  private final String userId;
  
  //In memory credentials wallet by Home AAM id -> Client ID -> User ID -> Credentials
  private Map<String, BoundCredentials> credentialsWallet =
      new HashMap<>();
  
  //Associate tokens with credentials
  private Map<String, BoundCredentials> tokenCredentials = new HashMap<>();
  
  private AAM coreAAM = null;
  
  
  /**
   * Creates a new instance of the Security Handler
   *
   * @param keystorePassword required to unlock the persisted keystore for this client
   * @throws SecurityHandlerException on instantiation errors
   */
  public SecurityHandler(String keystorePath,
                         String keystorePassword,
                         String homeAAMAddress,
                         //TODO: Dirty hack to be removed as it should be present in persistent storage in the future
                         String userId)
      throws SecurityHandlerException {
    // enabling support for elliptic curve certificates
    ECDSAHelper.enableECDSAProvider();
    
    // rest of the constructor code
    this.keystorePath = keystorePath;
    this.keystorePassword = keystorePassword;
    this.homeAAMAddress = homeAAMAddress;
    this.userId = userId;
    
    try {
      buildCredentialsWallet();
    } catch (Exception e) {
      throw new SecurityHandlerException("Error generating credentials wallet", e);
    }
  }

  public Map<String, AAM> getAvailableAAMs() throws SecurityHandlerException {
    return getAvailableAAMs(coreAAM);
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
          /*
          // TODO we need to base64 the certs in AAMClient implementation
          return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getForeignToken(homeToken,
              Optional.ofNullable(certificateStr),
              Optional.ofNullable(credentials.homeCredentials.homeAAM.getAamCACertificate().getCertificateString())));
              */
          // dirty bug fix for the moment
          return new Token(ClientFactory.getAAMClient(aam.getAamAddress()).getForeignToken(homeToken,
                  Optional.empty(),
                  Optional.empty()));
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
    
    char[] pw = password.toCharArray();
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
  
    File ksFile = new File(path);
    
    if (!ksFile.exists()) {
      trustStore.load(null, pw);
  
      // Store away the keystore.
      FileOutputStream fos = new FileOutputStream(ksFile);
      trustStore.store(fos, pw);
      fos.close();
    }
    
    FileInputStream fIn = new FileInputStream(ksFile);
    trustStore.load(fIn, password.toCharArray());

    fIn.close();
    return trustStore;
  }
  
  public ValidationStatus validate(AAM validationAuthority, String token,
                                   Optional<String> clientCertificate,
                                   Optional<String> clientCertificateSigningAAMCertificate,
                                   Optional<String> foreignTokenIssuingAAMCertificate) {
    
    
    return ClientFactory.getAAMClient(validationAuthority.getAamAddress()).validateCredentials(token,
        clientCertificate,
        clientCertificateSigningAAMCertificate,
        foreignTokenIssuingAAMCertificate);
  }
  
  @Override
  public Map<String, BoundCredentials> getAcquiredCredentials() {
    return credentialsWallet;
  }

  @Override
  public Certificate getComponentCertificate(String componentIdentifier, String platformIdentifier) {
      Certificate certificate = new Certificate();
      try {
          AAMClient aamClient = ClientFactory.getAAMClient(coreAAM.getAamAddress());
          // checking cache
          if (credentialsWallet.containsKey(platformIdentifier) && credentialsWallet.containsKey(componentIdentifier))
              // fetching from wallet
              certificate = credentialsWallet.get(platformIdentifier).homeCredentials.homeAAM.getComponentCertificates().get(componentIdentifier);
          else {
              // need to fetch fresh certificate
              certificate = new Certificate(aamClient.getComponentCertificate(componentIdentifier, platformIdentifier));
          }
      } catch (AAMException e) {
          logger.error(e);
      }
      return certificate;
  }
  
  @Override
  public AAM getCoreAAMInstance() {
    return coreAAM;
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
      
      String csr = null;
      if (clientId.contains("@")) {
        String[] componentInfo = clientId.split("@");
        csr = CryptoHelper.buildComponentCertificateSigningRequestPEM(
            componentInfo[0], componentInfo[1], pair);
      } else {
        csr = CryptoHelper.buildCertificateSigningRequestPEM(
            homeAAM.getAamCACertificate().getX509(), username, clientId, pair);
      }

      CertificateRequest request = new CertificateRequest(username,password,clientId,csr);

      String certificateValue = ClientFactory.getAAMClient(homeAAM.getAamAddress())
                                    .signCertificateRequest(request);
      
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
  private void buildCredentialsWallet() throws SecurityHandlerException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException {
    
    KeyStore trustStore = getKeystore();
    
    AAM homeAAM = new AAM();
    homeAAM.setAamAddress(homeAAMAddress);
    
    Map<String, AAM> aamList = getAvailableAAMs(homeAAM);
    if (aamList != null && !aamList.isEmpty()
            && aamList.get(SecurityConstants.CORE_AAM_INSTANCE_ID) != null) {
      coreAAM = aamList.get(SecurityConstants.CORE_AAM_INSTANCE_ID);
    } else {
      throw new SecurityHandlerException("Can't find the Core AAM instance");
    }
    
    Enumeration<String> aliases = trustStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      
      PrivateKey pvKey = (PrivateKey) trustStore.getKey(alias, keystorePassword.toCharArray());
      X509Certificate cert = (X509Certificate) trustStore.getCertificate(alias);
      
      String subject = cert.getSubjectX500Principal().getName();
      String aamSubject = cert.getIssuerX500Principal().getName();
  
      X500Name x500name = new JcaX509CertificateHolder(cert).getIssuer();
      RDN cn = x500name.getRDNs(BCStyle.CN)[0];
      String aamId = cn.getFirst().getValue().toString();
      
      
      if (subject.startsWith("CN=")) {
        String[] elements = subject.split("CN=")[1].split("@");
        if (elements.length > 1) {
          
          String user = null;
          String client = null;
          
          if (elements.length > 2) {
            user = elements[0];
            client = elements[1];
          } else {
            user = this.userId;
            client = elements[0] + "@" + elements[1];
          }
          
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
    fOut.close();
    return true;
  }
  
}
