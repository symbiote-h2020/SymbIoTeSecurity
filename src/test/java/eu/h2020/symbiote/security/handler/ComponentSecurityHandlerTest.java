package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import io.jsonwebtoken.Claims;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author Mikołaj Dobski (PSNC)
 */

@RunWith(PowerMockRunner.class)
@PrepareForTest(ClientFactory.class)
@PowerMockIgnore({"java.net.ssl", "javax.security.auth.x500.X500Principal"})
public class ComponentSecurityHandlerTest {

    private static final String ISSUING_AAM_CERTIFICATE_ALIAS = "core-1";
    private static final String CLIENT_CERTIFICATE_ALIAS = "client-core-1";
    private final String goodPlatformId = "aamid1";
    private final String badPlatformId = "wrongPlatform";
    private final String goodComponentId = "Component-id_1";
    private final String badComponentId = "Comp.onent2";
    private final String username = "testUser";
    private final String clientId = "testClient";
    private final String goodResourceID = "goodResourceID";
    private final String nameAttr = "name";
    String serverkeystorePath = "./src/test/resources/core.p12";
    String serverkeystorePassword = "1234567";
    String serveralias = "client-core-1";
    String homeAAMId = SecurityConstants.CORE_AAM_INSTANCE_ID;
    private AAMClient aamClient = Mockito.mock(AAMClient.class);
    private HashSet<AuthorizationCredentials> homePlatformAuthorizationCredentialsSet = new HashSet<>();
    private Map<String, IAccessPolicy> resourceAccessPolicyMap;

    @Before
    public void prepare() throws Throwable {


        ECDSAHelper.enableECDSAProvider();

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

        ks.load(new FileInputStream(serverkeystorePath), serverkeystorePassword.toCharArray());

        // issuing AAM platform (core-1 in this case)
        X509Certificate issuingAAMCertificate = (X509Certificate) ks.getCertificate(ISSUING_AAM_CERTIFICATE_ALIAS);
        PublicKey issuingAAMPublicKey = issuingAAMCertificate.getPublicKey();
        PrivateKey issuingAAMPrivateKey = (PrivateKey) ks.getKey(ISSUING_AAM_CERTIFICATE_ALIAS, serverkeystorePassword.toCharArray());

        // client
        X509Certificate clientCertificate = (X509Certificate) ks.getCertificate(CLIENT_CERTIFICATE_ALIAS);
        PublicKey clientPublicKey = clientCertificate.getPublicKey();
        PrivateKey clientPrivateKey = (PrivateKey) ks.getKey(CLIENT_CERTIFICATE_ALIAS, serverkeystorePassword.toCharArray());

        // client home credentials
        AAM issuingAAM = new AAM("", SecurityConstants.CORE_AAM_INSTANCE_ID, "", new Certificate(CryptoHelper.convertX509ToPEM(issuingAAMCertificate)), new HashMap<>());
        HomeCredentials homeCredentials = new HomeCredentials(issuingAAM, username, clientId, new Certificate(CryptoHelper.convertX509ToPEM(clientCertificate)), clientPrivateKey);

        Map<String, String> attributes = new HashMap<>();
        attributes.put(nameAttr, username);

        String authorizationToken = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributes,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                SecurityConstants.CORE_AAM_INSTANCE_ID,
                issuingAAMPublicKey,
                issuingAAMPrivateKey);
        AuthorizationCredentials authorizationCredentials = new AuthorizationCredentials(new Token(authorizationToken), issuingAAM, homeCredentials);
        this.homePlatformAuthorizationCredentialsSet.add(authorizationCredentials);


        resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMap = new HashMap<>();
        accessPolicyClaimsMap.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, username);
        accessPolicyClaimsMap.put(Claims.ISSUER, SecurityConstants.CORE_AAM_INSTANCE_ID);

        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.SLHTAP,
                accessPolicyClaimsMap
        );

        resourceAccessPolicyMap.put(goodResourceID, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));

        PowerMockito.mockStatic(ClientFactory.class);

        // startup check
        Mockito.when(aamClient.getComponentCertificate(Mockito.anyString(), Mockito.anyString())).thenReturn(homeCredentials.certificate.getCertificateString());

        //aamClient.signCertificateRequest
        Mockito.when(aamClient.signCertificateRequest(Mockito.any(CertificateRequest.class))).thenReturn(getCertString(serverkeystorePath, serverkeystorePassword, serveralias));

        Mockito.when(ClientFactory.getAAMClient(Matchers.anyString())).thenReturn(aamClient);

        //aamClient.getAvailableAAMs
        Mockito.when(aamClient.getAvailableAAMs()).thenReturn(new AvailableAAMsCollection(getAMMMap(issuingAAM)));
        Mockito.when(aamClient.getAAMsInternally()).thenReturn(new AvailableAAMsCollection(getAMMMap(issuingAAM)));

        //aamClient.getHomeToken
        Mockito.when(aamClient.getHomeToken(Matchers.anyString())).thenReturn(getTokenString(serverkeystorePath, serverkeystorePassword, serveralias));

        Mockito.when(aamClient.validateCredentials(Matchers.anyString(), Matchers.any(), Matchers.any(), Matchers.any())).thenReturn(ValidationStatus.VALID);

    }

    public AAM getHomeAMM(String aamInstanceId, String serverCertString) throws Throwable {

        String aamAddress = "https:\\www.aamserver";
        String aamInstanceFriendlyName = "name-friendly-" + aamInstanceId;
        Certificate certificate = new Certificate();
        certificate.setCertificateString(serverCertString);

        return new AAM(aamAddress, aamInstanceId, aamInstanceFriendlyName, certificate, new HashMap<>());
    }

    public Map<String, AAM> getAMMMap(AAM homeAAM) throws Throwable {
        Map<String, AAM> aamMap = new HashMap<>();

        aamMap.put(homeAAM.getAamInstanceId(), homeAAM);

        String platformCertString = getCertString("./src/test/resources/core.p12", serverkeystorePassword, "aamid1");
        aamMap.put("aamid1", getHomeAMM("aamid1", platformCertString));

        return aamMap;
    }

    public String getTokenString(String keystoreFilename, String spassword, String alias) throws Throwable {

        String result;

        char[] password = spassword.toCharArray();

        FileInputStream fIn = new FileInputStream(keystoreFilename);
        KeyStore keystore = KeyStore.getInstance("JKS");

        //Leer
        keystore.load(fIn, password);
        java.security.cert.Certificate cert = keystore.getCertificate(alias);

        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("name", username);

        byte[] userPublicKey = (cert.getPublicKey()).getEncoded();
        Long tokenValidity = SecurityHandlerTest.DateUtil.addDays(new Date(), 1).getTime();
        String deploymentID = SecurityConstants.CORE_AAM_INSTANCE_ID;
        PublicKey aamPublicKey = cert.getPublicKey();

        Key key = keystore.getKey(alias, spassword.toCharArray());

        result = DummyTokenIssuer.buildAuthorizationToken(clientId, attributes, userPublicKey, Token.Type.HOME, tokenValidity, deploymentID, aamPublicKey, (PrivateKey) key);

        return result;
    }

    public String getCertString(String keystoreFilename, String spassword, String alias) throws Throwable {
        return CryptoHelper.convertX509ToPEM((X509Certificate) getCertificate(keystoreFilename, spassword, alias));
    }

    public java.security.cert.Certificate getCertificate(String keystoreFilename, String spassword, String alias) throws
            Throwable {

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

        //Leer
        keystore.load(new FileInputStream(keystoreFilename), spassword.toCharArray());
        return keystore.getCertificate(alias);
    }

    @Test
    public void testComponentSecurityHandlerSuccess() throws Throwable {

        IComponentSecurityHandler a = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                serverkeystorePath,
                serverkeystorePassword,
                goodComponentId + "@" + goodPlatformId,
                "http://test",
                username,
                "irrelevant",
                Optional.empty()
        );
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.homePlatformAuthorizationCredentialsSet, true);

        Set<String> b = a.getSatisfiedPoliciesIdentifiers(this.resourceAccessPolicyMap, securityRequest);

        assertEquals(1, b.size());
        assertEquals(goodResourceID, b.toArray()[0]);

        ISecurityHandler c = a.getSecurityHandler();
        assertEquals(c.getAvailableAAMs().size(), 2);

        Token d = c.login(getHomeAMM(homeAAMId, getCertString("./src/test/resources/core.p12", serverkeystorePassword, "aamid1")));
        assertNotNull(d.getToken());
    }

    @Test(expected = SecurityHandlerException.class)
    public void testComponentSecurityHandlerNonExistingCert() throws SecurityHandlerException {

        IComponentSecurityHandler a = ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                serverkeystorePath,
                serverkeystorePassword,
                goodComponentId + "@" + badPlatformId,
                "http://test",
                "testUser",
                "irrelevant",
                Optional.empty()
        );
    }

    @Test(expected = SecurityHandlerException.class)
    public void badComponentIdTest() throws
            SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                badComponentId + "@" + goodPlatformId,
                "irrelevant",
                "irrelevant",
                "irrelevant",
                Optional.empty()
        );
    }


    @Test(expected = SecurityHandlerException.class)
    public void badPlatformIdTest() throws
            SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                goodComponentId + "@" + badPlatformId,
                "irrelevant",
                "irrelevant",
                "irrelevant",
                Optional.empty()
        );
    }

    @Test(expected = SecurityHandlerException.class)
    public void missingPartOfTheIdTest() throws
            SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                goodComponentId,
                "irrelevant",
                "irrelevant",
                "irrelevant",
                Optional.empty()
        );
    }

    @Test(expected = SecurityHandlerException.class)
    public void tooManyIdParts() throws
            SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                goodComponentId + "@" + goodPlatformId + "@" + goodPlatformId,
                "irrelevant",
                "irrelevant",
                "irrelevant",
                Optional.empty()
        );
    }

    @Test(expected = SecurityHandlerException.class)
    public void noConnectionComponentIdTest() throws
            SecurityHandlerException {

        ISecurityHandler mock = PowerMockito.mock(ISecurityHandler.class);

        ComponentSecurityHandler componentSecurityHandler = new ComponentSecurityHandler(
                mock,
                "irrelevant",
                "irrelevant",
                "irrelevant",
                goodComponentId + "@" + goodPlatformId,
                Optional.empty()
        );
    }

    @After
    public void deleteKeystore() {
        File file = new File("irrelevant");
        file.delete();
    }

}