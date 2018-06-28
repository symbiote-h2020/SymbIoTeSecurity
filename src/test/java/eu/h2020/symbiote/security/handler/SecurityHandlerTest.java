package eu.h2020.symbiote.security.handler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.payloads.*;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(PowerMockRunner.class)
@PrepareForTest(ClientFactory.class)
@PowerMockIgnore({"java.net.ssl", "javax.security.auth.x500.X500Principal"})
public class SecurityHandlerTest {


    private AAMClient aamClient = Mockito.mock(AAMClient.class);

    private static Log logger = LogFactory.getLog(SecurityHandlerTest.class);
    SecurityHandler testclient = null;

    String localPath = ".";
    String keystorePath = localPath + "/src/test/resources/keystore.jks";
    String keystorePassword = "123456";

    String serverkeystorePath = localPath + "/src/test/resources/core.p12";
    String serverkeystorePassword = "1234567";
    String serveralias = "client-core-1";
    String homeAAMId = SecurityConstants.CORE_AAM_INSTANCE_ID;
    
    String serverCertString = null;
    AAM homeAAM = null;

    @Before
    public void prepare() throws
            Throwable {


        PowerMockito.mockStatic(ClientFactory.class);
        
        serverCertString = getCertString(serverkeystorePath, serverkeystorePassword, serveralias);
    
        homeAAM = getHomeAMM(homeAAMId);
    
        //aamClient.signCertificateRequest
        Mockito.when(aamClient.signCertificateRequest(Mockito.any(CertificateRequest.class))).thenReturn(serverCertString);

        Mockito.when(ClientFactory.getAAMClient(Matchers.anyString())).thenReturn(aamClient);

        //aamClient.getAvailableAAMs
        Mockito.when(aamClient.getAvailableAAMs()).thenReturn(new AvailableAAMsCollection(getAMMMap()));

        //aamClient.getHomeToken
        Mockito.when(aamClient.getHomeToken(Matchers.anyString())).thenReturn(getTokenString(serverkeystorePath, serverkeystorePassword, serveralias));

        //aamClient.getForeignToken
        Mockito.when(aamClient.getForeignToken(Matchers.anyString(), Matchers.any(), Matchers.any())).thenReturn(getTokenString(serverkeystorePath, serverkeystorePassword, serveralias));

        //aamClient.getGuestToken
        Mockito.when(aamClient.getGuestToken()).thenReturn(getTokenString(serverkeystorePath, serverkeystorePassword, serveralias));

        //aamClient.getGuestToken
        Mockito.when(aamClient.validateCredentials(Matchers.anyString(), Matchers.any(), Matchers.any(), Matchers.any())).thenReturn(ValidationStatus.VALID);
    
    
        
        createEmptyKeystore();
        testclient = new SecurityHandler(keystorePath, keystorePassword, "http://test");
    
    
    }
    
    @After
    public void clean() {
        deleteKeystore();
    }
    
    private void deleteKeystore(){
        File file = new File(keystorePath);
        file.delete();
    }

    private void createEmptyKeystore() throws
            Exception {
        deleteKeystore();
    
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    
        char[] password = keystorePassword.toCharArray();
        ks.load(null, password);

        // Store away the keystore.
        FileOutputStream fos = new FileOutputStream(keystorePath);
        ks.store(fos, password);
        fos.close();
    }

    @Test
    public void testGetAvailableAAMs() throws
            Throwable {

        logger.info("----------------------------");
        logger.info("testGetAvailableAAMs starts");
        String aamInstanceId = "id-instance-123";
        Map<String, AAM> result = testclient.getAvailableAAMs(getHomeAMM(aamInstanceId));

        logger.info("TEST RESULT --> Map<String, AAM>: " + result);
        assert result != null;

        assert equalsId(result, getAMMMap());
    
        result = testclient.getAvailableAAMs();
    
        logger.info("TEST RESULT --> Map<String, AAM>: " + result);
        assert result != null;
    
        assert equalsId(result, getAMMMap());


    }

    private boolean equalsId(Map<String, AAM> result, Map<String, AAM> ammList) {

        boolean res = true;

        if (result.size() != ammList.size()) return false;

        Iterator<Entry<String, AAM>> entries = result.entrySet().iterator();
        while (entries.hasNext()) {
            Entry<String, AAM> entry = entries.next();
            String key = entry.getKey();

            if (ammList.get(key) == null)
                res = false;
        }

        return res;
    }

    @Test
    public void testGetCertificate() throws
            Throwable {

        logger.info("----------------------------");
        logger.info("testGetCertificate starts");

        String aamInstanceId = "id-instance-123";
        Certificate cer = testclient.getCertificate(homeAAM, "usu1", "pass1", "clientID");

        logger.info("TEST RESULT --> Certificate from AMM: " + cer);
        assert cer != null;
        assert (cer.getCertificateString()).equals(serverCertString);
    }
    


    @Test
    public void testLoginHomeCredentials() throws
            Throwable {
        logger.info("----------------------------");
        logger.info("testLoginHomeCredentials starts");
    
        testclient.getCertificate(homeAAM, "usu1", "pass1", "clientID");
    
        Token tk = testclient.login(homeAAM);
        String validToken = getTokenString(serverkeystorePath, serverkeystorePassword, serveralias);

        logger.info("TEST RESULT --> Token from AMM: " + tk);
        assert tk != null;
        logger.info(tk.getToken());
        logger.info(validToken);
        logger.info("validToken.length(): " + validToken.length());
        assert ((tk.getToken()).substring(0, 320)).equalsIgnoreCase(validToken.substring(0, 320));

    }


    @Test
    public void testLoginListOfAAMHomeCredentials() throws
            Throwable {
        logger.info("----------------------------");
        logger.info("testLoginListOfAAMHomeCredentials starts");
    
        testclient.getCertificate(homeAAM, "usu1", "pass1", "clientID");
        
        Token tk = testclient.login(homeAAM);
        String validToken = tk.getToken();
        //String validToken = getTokenString(serverkeystorePath, serverkeystorePassword, serveralias);
        List<AAM> ammlist = testclient.getAvailableAAMs(homeAAM).values().stream().collect(Collectors.toList());
        
        Map<AAM, Token> maptk = testclient.login(ammlist, validToken);

        logger.info("TEST RESULT --> Map Token from AMM: " + maptk);

        assert maptk != null;
        AAM oamm = getAMMfromList(ammlist, homeAAMId);
        logger.info(maptk.get(oamm));
        logger.info(validToken);
        logger.info("validToken.length(): " + validToken.length());
        assert ((maptk.get(oamm).getToken()).substring(0, 320)).equalsIgnoreCase(validToken.substring(0, 320));

    }

    @Test
    public void testLoginAsGuest() throws
            Throwable {
        logger.info("----------------------------");
        logger.info("testLoginAsGuest starts");

        Token tk = testclient.loginAsGuest(getHomeAMM(homeAAMId));
        String sToken = tk.getToken();
        String validToken = getTokenString(serverkeystorePath, serverkeystorePassword, serveralias);

        logger.info("TEST RESULT --> Token from AMM as Guest: " + tk);

        assert tk != null;
        logger.info(sToken);
        logger.info(validToken);
        logger.info("validToken.length(): " + validToken.length());
        assert (sToken.substring(0, 320)).equalsIgnoreCase(validToken.substring(0, 320));

    }

    @Test
    public void testValidate() throws
            Throwable {
        logger.info("----------------------------");
        logger.info("testValidate starts");

        String validToken = getTokenString(serverkeystorePath, serverkeystorePassword, serveralias);

        FileInputStream fIn = new FileInputStream(serverkeystorePath);
        KeyStore keystore = KeyStore.getInstance("JKS");

//	    //Leer
//		char[] password = serverkeystorePassword.toCharArray();
//		keystore.load(fIn, password);
//		java.security.cert.Certificate cert = keystore.getCertificate(serveralias);
//

        ValidationStatus val = testclient.validate(getHomeAMM(homeAAMId), validToken, null, null, null);

        logger.info("TEST RESULT --> ValidationStatus from AMM and Token: " + val);
        assert val != null;
        assert (val == ValidationStatus.VALID);
    }

    private AAM getAMMfromList(List<AAM> ammlist, String testaamInstanceId2) {
        for (int x = 0; x < ammlist.size(); x++) {

            AAM a = ammlist.get(x);
            if (a.getAamInstanceId().equals(testaamInstanceId2))
                return a;
        }
        return null;
    }

    public AAM getHomeAMM(String aamInstanceId) throws
            Throwable {

        String aamAddress = "https:\\www.aamserver";
        String aamInstanceFriendlyName = "name-friendly-" + aamInstanceId;
        Certificate certificate = new Certificate(serverCertString);

        return new AAM(aamAddress, aamInstanceId, aamInstanceFriendlyName, certificate, new HashMap<>());
    }

    public java.security.cert.Certificate getCertificate(String keystoreFilename, String spassword, String alias) throws
            Throwable {
        
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
    
        //Leer
        keystore.load(new FileInputStream(keystoreFilename), spassword.toCharArray());
        return keystore.getCertificate(alias);
    }

    public String getCertString(String keystoreFilename, String spassword, String alias) throws
            Throwable {
        return CryptoHelper.convertX509ToPEM((X509Certificate) getCertificate(keystoreFilename, spassword, alias));
    }

    public Map<String, AAM> getAMMMap() throws
            Throwable {
        Map<String, AAM> aamMap = new HashMap<>();
        
        aamMap.put(homeAAMId, homeAAM);
        
        Certificate certificate = new Certificate(getCertString(serverkeystorePath, serverkeystorePassword, serveralias));

        for (int i = 0; i < 3; i++) {
            String key = "ammId" + i;
            aamMap.put(key, getHomeAMM(key));
        }

        return aamMap;
    }


    public String getTokenString(String keystoreFilename, String spassword, String alias) throws
            Throwable {

        String result;

        char[] password = spassword.toCharArray();

        KeyStore keystore;
        java.security.cert.Certificate cert;
        String userId;
        HashMap<String, String> attributes;
        byte[] userPublicKey;
        Long tokenValidity;
        String deploymentID;
        PublicKey aamPublicKey;
        Key key;
        try (FileInputStream fIn = new FileInputStream(keystoreFilename)) {
            keystore = KeyStore.getInstance("JKS");

            //Leer
            keystore.load(fIn, password);
        }
        cert = keystore.getCertificate(alias);

        userId = "testClient";
        attributes = new HashMap<>();
        attributes.put("name", "testClient");

        userPublicKey = (cert.getPublicKey()).getEncoded();
        tokenValidity = DateUtil.addDays(new Date(), 1).getTime();
        deploymentID = "testUser";
        aamPublicKey = cert.getPublicKey();

        key = keystore.getKey(alias, spassword.toCharArray());


        result = DummyTokenIssuer.buildAuthorizationToken(userId, attributes, userPublicKey, Token.Type.HOME, tokenValidity, deploymentID, aamPublicKey, (PrivateKey) key);


        return result;
    }

    static public class DateUtil {
        public static Date addDays(Date date, int days) {
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            cal.add(Calendar.DATE, days); //minus number would decrement the days
            return cal.getTime();
        }
    }

    @Test
    public void serializeIt() throws IOException {
        SecurityRequest securityRequest = new SecurityRequest(new HashSet<>(), 123, "bla");
        ObjectMapper om = new ObjectMapper();
        assertTrue(om.canSerialize(SecurityRequest.class));
        String string = (om.writerWithDefaultPrettyPrinter().writeValueAsString(securityRequest));
        System.out.println(string);
        SecurityRequest securityRequest1 = om.readValue(string, SecurityRequest.class);
        assertEquals(securityRequest, securityRequest1);

        string = "{\n" +
                "  \"securityCredentials\" : [ ],\n" +
                "  \"timestamp\" : 123,\n" +
                "  \"hash\" : \"\",\n" +
                "  \"extravalue\" : \"extravalue\"\n" +
                "}";
        System.out.println("before: "+string);
        securityRequest1 = om.readValue(string, SecurityRequest.class);
        string = (om.writerWithDefaultPrettyPrinter().writeValueAsString(securityRequest1));
        System.out.println("after: "+string);

        securityRequest = new SecurityRequest(new HashSet<>(), 123);
        om = new ObjectMapper();
        assertTrue(om.canSerialize(SecurityRequest.class));
        string = (om.writerWithDefaultPrettyPrinter().writeValueAsString(securityRequest));
        System.out.println(string);
        securityRequest1 = om.readValue(string, SecurityRequest.class);
        assertEquals(securityRequest, securityRequest1);

        string = "{\n" +
                "  \"securityCredentials\" : [ ],\n" +
                "  \"timestamp\" : 123\n" +
                "}";
        System.out.println("before:"+ string);
        securityRequest1 = om.readValue(string, SecurityRequest.class);
        string = (om.writerWithDefaultPrettyPrinter().writeValueAsString(securityRequest1));
        System.out.println("after: "+ string);



    }
}