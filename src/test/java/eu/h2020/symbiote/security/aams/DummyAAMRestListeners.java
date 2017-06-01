package eu.h2020.symbiote.security.aams;


import eu.h2020.symbiote.security.SecurityHandlerTest.DateUtil;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTClaims;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.bind.annotation.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;


/**
 * Dummy REST service mimicking exposed AAM features required by SymbIoTe users and reachable via CoreInterface in
 * the Core and Interworking Interfaces on Platforms' side.
 *
 * @author Mikołaj Dobski (PSNC)
 */
@RestController
@WebAppConfiguration
public class DummyAAMRestListeners {
    private static final Log log = LogFactory.getLog(DummyAAMRestListeners.class);

    public DummyAAMRestListeners() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @RequestMapping(method = RequestMethod.GET, path = AAMConstants.AAM_GET_CA_CERTIFICATE)
    public String getRootCertificate() throws NoSuchProviderException, KeyStoreException, IOException,
            UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        log.debug("invoked get token public");
        final String ALIAS = "test aam keystore";
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/TestAAM.keystore"), "1234567".toCharArray());
        X509Certificate x509Certificate = (X509Certificate) ks.getCertificate("test aam keystore");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(x509Certificate);
        pemWriter.close();
        return signedCertificatePEMDataStringWriter.toString();
    }

    /**
     * acts temporarily as core AAM
     */
    @RequestMapping(method = RequestMethod.POST, path = AAMConstants.AAM_LOGIN, produces =
            "application/json", consumes = "application/json")
    public ResponseEntity<?> doLogin(@RequestBody Credentials credential) {
        log.info("User trying to login " + credential.getUsername() + " - " + credential.getPassword());
        try {
            final String ALIAS = "test aam keystore";
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new FileInputStream("./src/test/resources/TestAAM.keystore"), "1234567".toCharArray());
            Key key = ks.getKey(ALIAS, "1234567".toCharArray());

            HashMap<String, String> attributes = new HashMap<>();
            attributes.put("name", "test2");
            String tokenString = JWTEngine.generateJWTToken(credential.getUsername(), attributes, ks.getCertificate
                    (ALIAS).getPublicKey().getEncoded(), IssuingAuthorityType.CORE, DateUtil.addDays(new Date(), 1)
                            .getTime(), AAMConstants.AAM_CORE_AAM_INSTANCE_ID, ks.getCertificate(ALIAS).getPublicKey(),
                    (PrivateKey) key);

            Token coreToken = new Token(tokenString);

            HttpHeaders headers = new HttpHeaders();
            headers.add(AAMConstants.TOKEN_HEADER_NAME, coreToken.getToken());

            /* Finally issues and return foreign_token */
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException |
                UnrecoverableKeyException | JWTCreationException | NoSuchProviderException | ValidationException
                e) {
            log.error(e);
        }
        return null;
    }


    @RequestMapping(method = RequestMethod.POST, path = AAMConstants.AAM_CHECK_HOME_TOKEN_REVOCATION,
            produces = "application/json;charset=UTF-8", consumes = "application/json;charset=UTF-8")
    public ResponseEntity<CheckRevocationResponse> checkTokenRevocation(@RequestHeader(AAMConstants
            .TOKEN_HEADER_NAME) String token) {
        log.info("Checking token revocation " + token);
        // todo implement... for the moment returns valid
        return new ResponseEntity<>(new CheckRevocationResponse
                (ValidationStatus.VALID), HttpStatus.OK);
    }

    /**
     * Acts either as core or platform AAM depending on what token was passed.
     */
    @RequestMapping(method = RequestMethod.POST, path = AAMConstants.AAM_REQUEST_FOREIGN_TOKEN, produces =
            "application/json;charset=UTF-8", consumes = "application/json;charset=UTF-8")
    public ResponseEntity<?> requestForeignToken(@RequestHeader(AAMConstants.TOKEN_HEADER_NAME) String
                                                         requestTokenString) {
        log.info("Requesting foreign (core or platform) token, received token " + requestTokenString);
        try {
            final String ALIAS = "test aam keystore";
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new FileInputStream("./src/test/resources/TestAAM.keystore"), "1234567".toCharArray());
            Key key = ks.getKey(ALIAS, "1234567".toCharArray());

            HashMap<String, String> federatedAttributes = new HashMap<>();
            federatedAttributes.put("fname1", "fvalue1");
            federatedAttributes.put("fname2", "fvalue2");
            federatedAttributes.put("fname3", "fvalue3");

            JWTClaims claimsFromRequestToken = JWTEngine.getClaimsFromToken(requestTokenString);
            String authorityId;
            IssuingAuthorityType authorityType;

            if (IssuingAuthorityType.valueOf(claimsFromRequestToken.getTtyp()) == IssuingAuthorityType.CORE) {
                // act as platform AAM
                authorityId = "SomePlatformAAM";
                authorityType = IssuingAuthorityType.PLATFORM;
            } else {
                // act as core AAM
                authorityId = AAMConstants.AAM_CORE_AAM_INSTANCE_ID;
                authorityType = IssuingAuthorityType.CORE;
            }

            String tokenString = JWTEngine.generateJWTToken(
                    claimsFromRequestToken.getSub(),
                    federatedAttributes,
                    Base64.decodeBase64(claimsFromRequestToken.getSpk()),
                    authorityType, DateUtil.addDays(new Date(), 1).getTime
                            (), authorityId, ks.getCertificate(ALIAS).getPublicKey(), (PrivateKey) key);

            Token foreignToken = new Token(tokenString);
            HttpHeaders headers = new HttpHeaders();
            headers.add(AAMConstants.TOKEN_HEADER_NAME, foreignToken.getToken());

            /* Finally issues and return foreign_token */
            return new ResponseEntity<>(headers, HttpStatus.OK);
        } catch (MalformedJWTException | KeyStoreException | NoSuchAlgorithmException | CertificateException |
                IOException |
                UnrecoverableKeyException | NoSuchProviderException | JWTCreationException | ValidationException
                e) {
            log.error(e);
        }
        return null;
    }

    @RequestMapping(value = AAMConstants.AAM_GET_AVAILABLE_AAMS, method = RequestMethod.GET, produces =
            "application/json")
    public ResponseEntity<List<AAM>> getAvailableAAMs() {
        List<AAM> availableAAMs = new ArrayList<>();
        try {
            // Core AAM
            Certificate coreCertificate = new Certificate("coreCertTestValue");
            // fetching the identifier from certificate
            String coreAAMInstanceIdentifier = "Symbiote Core";

            // adding core aam info to the response
            availableAAMs.add(new AAM("https://localhost:8100", "SymbIoTe Core AAM", coreAAMInstanceIdentifier,
                    coreCertificate));

            return new ResponseEntity<>(availableAAMs, HttpStatus.OK);
        } catch (Exception e) {
            log.error(e);
            return new ResponseEntity<>(new ArrayList<AAM>(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}

