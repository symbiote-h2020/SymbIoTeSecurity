package eu.h2020.symbiote.security;

import eu.h2020.symbiote.security.aams.DummyAAMAMQPListener;
import eu.h2020.symbiote.security.certificate.Certificate;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.SecurityHandlerException;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.session.AAM;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.FileInputStream;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.*;

/**
 * This class handles the initialization from the platform. Initially created by jose
 *
 * @author Elena Garrido (Atos)
 * @author Mikołaj Dobski (PSNC)
 *         \class PlatformInformationManager
 *         \brief PlatformInformationManager handles the registration of the resources within the platform
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT, properties = {"symbiote.testaam" +
        ".url=http://localhost:18033", "symbiote.coreaam.url=http://localhost:18033"})
@ContextConfiguration(locations = {"classpath:test-properties.xml"})
@Configuration
@ComponentScan
@EnableAutoConfiguration
@DirtiesContext
public class InternalSecurityHandlerTest {

    private static final Log log = LogFactory.getLog(InternalSecurityHandlerTest.class);
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    private InternalSecurityHandler securityHandler;
    private String coreTokenString;
    private String platformTokenString;
    private String symbioteCoreInterfaceAddress;
    private AAM coreAAM;
    private String rabbitMQHostIP;
    private DummyAAMAMQPListener dummyAAMAMQPListener = new DummyAAMAMQPListener();

    @Before
    public void setUp() throws Exception {
        dummyAAMAMQPListener.init();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        symbioteCoreInterfaceAddress = "http://localhost:18033";
        rabbitMQHostIP = "localhost";
        securityHandler = new InternalSecurityHandler(symbioteCoreInterfaceAddress, rabbitMQHostIP, "guest", "guest");

        final String ALIAS = "test aam keystore";
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream("./src/test/resources/TestAAM.keystore"), "1234567".toCharArray());
        Key key = ks.getKey(ALIAS, "1234567".toCharArray());

        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("name", "test2");
        coreTokenString = JWTEngine.generateJWTToken("test1", attributes, ks.getCertificate(ALIAS).getPublicKey()
                        .getEncoded(), IssuingAuthorityType.CORE, DateUtil.addDays(new Date(), 1).getTime(),
                "securityHandlerTestCoreAAM", ks.getCertificate(ALIAS).getPublicKey(), (PrivateKey) key);
        platformTokenString = JWTEngine.generateJWTToken("test1", attributes, ks.getCertificate(ALIAS).getPublicKey()
                        .getEncoded(), IssuingAuthorityType.PLATFORM, DateUtil.addDays(new Date(), 1).getTime(),
                "securityHandlerTestPlatformAAM", ks.getCertificate(ALIAS).getPublicKey(), (PrivateKey) key);

        // coreAAM
        X509Certificate x509Certificate = (X509Certificate) ks.getCertificate("test aam keystore");
        StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
        pemWriter.writeObject(x509Certificate);
        pemWriter.close();
        // XXX the instance id "PlatformAAM" is hardcoded in the keystore
        coreAAM = new AAM(symbioteCoreInterfaceAddress, "Core AAM", "PlatformAAM", new Certificate
                (signedCertificatePEMDataStringWriter.toString()));
    }

    @Test
    public void testRequestFederatedCoreToken() {
        try {
            Token token = securityHandler.requestFederatedCoreToken("user", "password");
            Assert.assertTrue(IssuingAuthorityType.CORE == token.getType());
        } catch (SecurityHandlerException e) {
            log.error(e);
            assert (false);
        }
    }

    @Test
    public void testRequestFederatedToken() {
        Token token = securityHandler.requestCoreToken("user", "password");

        log.info("Test Client received this Token: " + token.toString());

        assertNotNull(token.getToken());
        assertEquals(IssuingAuthorityType.CORE, token.getType());

        List<AAM> aams = new ArrayList<>();
        // stubbing a dummy platform aam
        aams.add(new AAM(symbioteCoreInterfaceAddress, "A test platform aam", "SomePlatformAAM", new Certificate()));
        Map<String, Token> tokens = securityHandler.requestForeignTokens(aams);
        assertTrue(tokens.containsKey("SomePlatformAAM"));
        assertEquals(IssuingAuthorityType.PLATFORM, tokens.get("SomePlatformAAM").getType());
    }

    @Test
    public void testHomeTokenValidation() {
        try {
            Token token = new Token(coreTokenString);
            ValidationStatus validationStatus = securityHandler.verifyHomeToken(token);
            assertEquals(ValidationStatus.VALID, validationStatus);
            Assert.assertEquals("test1", token.getClaims().getSubject());
            Assert.assertEquals("test2", token.getClaims().get(AAMConstants.SYMBIOTE_ATTRIBUTES_PREFIX + "name"));
        } catch (ValidationException e) {
            log.error(e);
            assert (false);
        }
    }

    @Test
    public void testHomeTokenValidationWithError() throws ValidationException {
        thrown.expect(ValidationException.class);
        String tokenString =
                "eyJhbGciOiJSUzUxMiJ9.eyJzdWIiOiJ0ZXN0MSIsImV4cCI6MTQ5MTAzNzk5MiwibmFtZSI6InRlc3QyIn0.j8EPRRVi5L63" +
                        "-s5r8lI9vq_Pi_NoPy4Q-jn39xg8zETTpYecoC26xMo5XaE-sJjhZ1Mup" +
                        "-W1njV3g7QMVJUY2G_gqzezuSc1oUs9ZVYabGKI4W8D1jkWZo9-FQTPJw8_Zy8jeU1UZD8Vwcn6u51zw7dDuFA" +
                        "-tcFoYpK99GyCAqkukm1H7dCfAr-bIWeiOEI8p2KHc2" +
                        "-3vZto39hGMrexCigWI1dSICw2rG1mESyZgxrT4cs1UEQp1KuQ1WK2nUOhjeNTozpvqs65weKw4aCiQgvp36" +
                        "-UxUvRJPl7KBydvFf564T0gHEtgmXSZMQGHwUI9x6RUFR4NuvtGeAFU2pcx";
        Token token = new Token(tokenString);
        ValidationStatus validationStatus = securityHandler.verifyHomeToken(token);
        assertEquals(ValidationStatus.INVALID, validationStatus);
    }


    static public class DateUtil {
        public static Date addDays(Date date, int days) {
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            cal.add(Calendar.DATE, days); //minus number would decrement the days
            return cal.getTime();
        }
    }
}

