package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.AAMClient;
import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;

@RunWith(PowerMockRunner.class)
@PrepareForTest(ClientFactory.class)
@PowerMockIgnore({"java.net.ssl", "javax.security.auth.x500.X500Principal"})
public class SecurityHandlerTest {


    private AAMClient aamClient = Mockito.mock(AAMClient.class);

    private static Log logger = LogFactory.getLog(SecurityHandlerTest.class);
    SecurityHandler client = null;
    SecurityHandler Testclient = null;

    String localPath = ".";
    String keystorePath = localPath + "/src/test/resources/keystore.jks";
    String skeystorePassword = "123456";
    String aamInstanceId = "id-instance-123";

    boolean bisOnline = false;

    String TestkeystorePath = localPath + "/src/test/resources/core.p12";
    String TestkeystorePassword = "1234567";
    String Testalias = "client-core-1";
    String TestaamInstanceId = "SymbIoTe_Core_AAM";

    @Before
    public void prepare() throws Throwable {


        PowerMockito.mockStatic(ClientFactory.class);

        client = new SecurityHandler(keystorePath, skeystorePassword, bisOnline);

        Testclient = new SecurityHandler(TestkeystorePath, TestkeystorePassword, bisOnline);

        //aamClient.getClientCertificate
        String validCert = getCertString(TestkeystorePath, TestkeystorePassword, Testalias);
        Mockito.when(aamClient.getClientCertificate(Mockito.any(CertificateRequest.class))).thenReturn(validCert);

        Mockito.when(ClientFactory.getAAMClient(Matchers.anyString())).thenReturn(aamClient);


        //aamClient.getAvailableAAMs()
        AvailableAAMsCollection listAAMs = Mockito.mock(AvailableAAMsCollection.class);
        Mockito.when(listAAMs.getAvailableAAMs()).thenReturn(getAMMMap());
        Mockito.when(aamClient.getAvailableAAMs()).thenReturn(listAAMs);

        //aamClient.getHomeToken


        Mockito.when(aamClient.getHomeToken(Matchers.anyString())).thenReturn(getTokenString(TestkeystorePath, TestkeystorePassword, Testalias));

        //aamClient.getForeignToken
        Mockito.when(aamClient.getForeignToken(Matchers.anyString(), Matchers.anyString())).thenReturn(getTokenString(TestkeystorePath, TestkeystorePassword, Testalias));

        //aamClient.getGuestToken
        Mockito.when(aamClient.getGuestToken()).thenReturn(getTokenString(TestkeystorePath, TestkeystorePassword, Testalias));

        //aamClient.getGuestToken
        Mockito.when(aamClient.validate(Matchers.anyString(), Matchers.anyString())).thenReturn(ValidationStatus.VALID);


    }

    @Test
    public void testGetAvailableAAMs() throws Throwable {

        logger.info("----------------------------");
        logger.info("testGetAvailableAAMs starts");
        String aamInstanceId = "id-instance-123";
        Map<String, AAM> result = client.getAvailableAAMs(getHomeAMM(aamInstanceId));

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
            String key = (String) entry.getKey();

            if (ammList.get(key) == null)
                res = false;
        }

        return res;
    }

    @Test
    public void testGetCertificate() throws Throwable {

        logger.info("----------------------------");
        logger.info("testGetCertificate starts");

        deletekeystore();
        String aamInstanceId = "id-instance-123";
        Certificate cer = client.getCertificate(getHomeAMM(aamInstanceId), "usu1", "pass1", "clientID");

        logger.info("TEST RESULT --> Certificate from AMM: " + cer);
        assert cer != null;
        assert (cer.getCertificateString()).equalsIgnoreCase(getCertString(keystorePath, skeystorePassword, aamInstanceId));


    }


    @Test
    public void testClearCachedTokens() {

        logger.info("----------------------------");
        logger.info("testClearCachedTokens starts");
        client.clearCachedTokens();

    }


    @Test
    public void testLoginHomeCredentials() throws Throwable {
        logger.info("----------------------------");
        logger.info("testLoginHomeCredentials starts");

        Token tk = Testclient.login(getHomeAMM(TestaamInstanceId));
        String validToken = getTokenString(TestkeystorePath, TestkeystorePassword, Testalias);

        logger.info("TEST RESULT --> Token from AMM: " + tk);
        assert tk != null;
        logger.info(tk.getToken());
        logger.info(validToken);
        logger.info("validToken.length(): " + validToken.length());
        assert ((tk.getToken()).substring(0, 320)).equalsIgnoreCase(validToken.substring(0, 320));

    }


    @Test
    public void testLoginListOfAAMHomeCredentials() throws Throwable {
        logger.info("----------------------------");
        logger.info("testLoginListOfAAMHomeCredentials starts");

        Token tk = Testclient.login(getHomeAMM(TestaamInstanceId));
        String validToken = tk.getToken();
        //String validToken = getTokenString(TestkeystorePath, TestkeystorePassword, Testalias);
        List<AAM> ammlist = getAMMList(TestaamInstanceId);
        Map<AAM, Token> maptk = Testclient.login(ammlist, validToken);

        logger.info("TEST RESULT --> Map Token from AMM: " + maptk);

        assert maptk != null;
        AAM oamm = getAMMfromList(ammlist, TestaamInstanceId);
        logger.info(maptk.get(oamm));
        logger.info(validToken);
        logger.info("validToken.length(): " + validToken.length());
        assert ((maptk.get(oamm).getToken()).substring(0, 320)).equalsIgnoreCase(validToken.substring(0, 320));

    }

    @Test
    public void testLoginAsGuest() throws Throwable, Throwable {
        logger.info("----------------------------");
        logger.info("testLoginAsGuest starts");

        Token tk = Testclient.loginAsGuest(getHomeAMM(TestaamInstanceId));
        String sToken = tk.getToken();
        String validToken = getTokenString(TestkeystorePath, TestkeystorePassword, Testalias);

        logger.info("TEST RESULT --> Token from AMM as Guest: " + tk);

        assert tk != null;
        logger.info(sToken);
        logger.info(validToken);
        logger.info("validToken.length(): " + validToken.length());
        assert (sToken.substring(0, 320)).equalsIgnoreCase(validToken.substring(0, 320));

    }

    @Test
    public void testValidate() throws Throwable {
        logger.info("----------------------------");
        logger.info("testValidate starts");

        String validToken = getTokenString(TestkeystorePath, TestkeystorePassword, Testalias);

        FileInputStream fIn = new FileInputStream(TestkeystorePath);
        KeyStore keystore = KeyStore.getInstance("JKS");

//	    //Leer
//		char[] password = TestkeystorePassword.toCharArray();
//		keystore.load(fIn, password);
//		java.security.cert.Certificate cert = keystore.getCertificate(Testalias);
//		

        Optional<Certificate> clientCertificate = Optional.empty();

        ValidationStatus val = Testclient.validate(getHomeAMM(TestaamInstanceId), validToken, clientCertificate, Optional.empty());

        logger.info("TEST RESULT --> ValidationStatus from AMM and Token: " + val);
        assert val != null;
        assert (val == ValidationStatus.VALID);
    }

    private AAM getAMMfromList(List<AAM> ammlist, String testaamInstanceId2) {
        // TODO Auto-generated method stub


        for (int x = 0; x < ammlist.size(); x++) {

            AAM a = (AAM) ammlist.get(x);
            if (a.getAamInstanceId().equals(testaamInstanceId2))
                return a;
        }
        return null;
    }

    public AAM getHomeAMM(String aamInstanceId) throws Throwable {

        String aamAddress = "https:\\www.aamserver";
        String aamInstanceFriendlyName = "name-friendly-xxx";
        Certificate certificate = new Certificate();

        InputStream fis = new FileInputStream(TestkeystorePath);
        BufferedInputStream bis = new BufferedInputStream(fis);

        String certificateString = getCertString(TestkeystorePath, TestkeystorePassword, Testalias);

        certificate.setCertificateString(certificateString);

        AAM home = new AAM(aamAddress, aamInstanceFriendlyName, aamInstanceId, certificate);

        return home;

    }

    public String getCertString(String keystoreFilename, String spassword, String alias) throws Throwable {

        String result = null;

        char[] password = spassword.toCharArray();

        FileInputStream fIn = new FileInputStream(keystoreFilename);
        KeyStore keystore = KeyStore.getInstance("JKS");

        //Leer
        keystore.load(fIn, password);
        java.security.cert.Certificate cert = keystore.getCertificate(alias);
//		System.out.println("cert:");
//		System.out.println("keystoreFilename: "+keystoreFilename);
//		System.out.println("spassword: "+spassword);
//		System.out.println("alias: "+alias);
//		System.out.println(cert);


        result = CryptoHelper.convertX509ToPEM((X509Certificate) cert);

        return result;
    }

    public void deletekeystore() throws Throwable {
        logger.info("deletekeystore()");
        FileInputStream fIn = new FileInputStream(keystorePath);
        KeyStore keystore = KeyStore.getInstance("JKS");
        char[] password = skeystorePassword.toCharArray();
        keystore.load(fIn, password);

        Enumeration<String> aliasList = keystore.aliases();

        while (aliasList.hasMoreElements()) {
            String alias = aliasList.nextElement();
            keystore.deleteEntry(alias);
            logger.info("alias: [" + alias + "] deleted");
        }

        FileOutputStream fOut = new FileOutputStream(keystorePath);
        keystore.store(fOut, password);

        logger.info(keystorePath + " empty");

    }


    public Map<String, AAM> getAMMMap() throws Throwable {
        Map<String, AAM> aamMap = new HashMap<>();
        Certificate certificate = new Certificate();

        for (int i = 0; i < 3; i++) {
            String key = "ammId" + i;
            String aamAddress = "https:\\www.aamserver" + i;
            String aamInstanceFriendlyName = "name-friendly-xxx" + i;
            String aamInstanceId = "id-instance-123" + i;
            AAM value = new AAM(aamAddress, aamInstanceFriendlyName, aamInstanceId, certificate);
            aamMap.put(key, value);
        }

        return aamMap;
    }


    public String getTokenString(String keystoreFilename, String spassword, String alias) throws Throwable {

        String result = null;

        char[] password = spassword.toCharArray();

        FileInputStream fIn = new FileInputStream(keystoreFilename);
        KeyStore keystore = KeyStore.getInstance("JKS");

        //Leer
        keystore.load(fIn, password);
        java.security.cert.Certificate cert = keystore.getCertificate(alias);
//		System.out.println("cert:");
//		System.out.println("keystoreFilename: "+keystoreFilename);
//		System.out.println("spassword: "+spassword);
//		System.out.println("alias: "+alias);
//		System.out.println(cert);	


        String userId = "testClient";
        HashMap<String, String> attributes = new HashMap<>();
        attributes.put("name", "testClient");

        byte[] userPublicKey = (cert.getPublicKey()).getEncoded();
        Long tokenValidity = DateUtil.addDays(new Date(), 1).getTime();
        String deploymentID = "testUser";
        PublicKey aamPublicKey = cert.getPublicKey();

        Key key = keystore.getKey(alias, spassword.toCharArray());


        result = DummyTokenIssuer.buildAuthorizationToken(userId, attributes, userPublicKey, Token.Type.HOME, tokenValidity, deploymentID, aamPublicKey, (PrivateKey) key);


        return result;
    }

    public List<AAM> getAMMList(String aamInsId) throws Throwable {

        ArrayList<AAM> listamm = new ArrayList<AAM>();

        Certificate certificate = new Certificate();
        String aamInstanceId = aamInsId;
        for (int i = 0; i < 3; i++) {
            String aamAddress = "https:\\www.aamserver" + i;

            String aamInstanceFriendlyName = "name-friendly-xxx" + i;

            if (i > 0)
                aamInstanceId = "id-instance-123" + i;

            AAM value = new AAM(aamAddress, aamInstanceFriendlyName, aamInstanceId, certificate);
            listamm.add(value);
        }

        return listamm;
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