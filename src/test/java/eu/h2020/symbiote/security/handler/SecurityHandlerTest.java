package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.AAMClient;
import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import eu.h2020.symbiote.security.helpers.CryptoHelper;

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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.fail;

@RunWith(PowerMockRunner.class)
@PrepareForTest(ClientFactory.class)
@PowerMockIgnore({"java.net.ssl", "javax.security.auth.x500.X500Principal"})
public class SecurityHandlerTest {
	
	
	private AAMClient aamClient = Mockito.mock(AAMClient.class);
	
	private static Log logger = LogFactory.getLog(SecurityHandlerTest.class);
	SecurityHandler client = null;
	
	String localPath = ".";
    String keystorePath = localPath + "/src/test/resources/keystore.jks";
    String skeystorePassword = "123456";
	String aamInstanceId = "id-instance-123";
    boolean bisOnline = false;
    
	String TestkeystorePath= localPath + "/src/test/resources/core.p12";
    String TestkeystorePassword = "1234567";
    String Testalias = "client-core-1";
    
	@Before
	public void prepare() throws Throwable {
		
	
		
		PowerMockito.mockStatic(ClientFactory.class);
	    
		client = new SecurityHandler(keystorePath, skeystorePassword, bisOnline);
	    
		//aamClient.getClientCertificate
		String validCert = getCertString(TestkeystorePath, TestkeystorePassword, Testalias);
		Mockito.when(aamClient.getClientCertificate(Mockito.any(CertificateRequest.class))).thenReturn(validCert);
		
		Mockito.when(ClientFactory.getAAMClient(Matchers.anyString())).thenReturn(aamClient);
		
		
		//aamClient.getAvailableAAMs()
		AvailableAAMsCollection listAAMs = Mockito.mock(AvailableAAMsCollection.class);
		Mockito.when(listAAMs.getAvailableAAMs()).thenReturn(getAMMList());		
		Mockito.when(aamClient.getAvailableAAMs()).thenReturn(listAAMs);
  			    


	}

	@Test
	public void testGetAvailableAAMs() throws Throwable {
		
		logger.info("testGetAvailableAAMs starts");
		
		Map<String, AAM> result = client.getAvailableAAMs(getHomeAMM());
		
		logger.info("TEST RESULT --> Map<String, AAM>: " + result );	
		assert result != null;	

		assert equalsId(result, getAMMList());
		
		
	}
	
	private boolean equalsId(Map<String, AAM> result, Map<String, AAM> ammList) {

		// TODO Auto-generated method stub
		return false;
	}

	//@Test
	public void testGetCertificate() throws Throwable {
		
		logger.info("testGetCertificate starts");
		
	    deletekeystore();
	    
		Certificate cer = client.getCertificate(getHomeAMM(), "usu1", "pass1", "clientID");

		logger.info("TEST RESULT --> Certificate from AMM: " + cer);
		assert cer != null;	
		assert (cer.getCertificateString()).equalsIgnoreCase(getCertString(keystorePath, skeystorePassword, aamInstanceId ));		

		
	
	}


	//@Test
	public void testClearCachedTokens() {
		fail("Not yet implemented");
	}


	//@Test
	public void testLoginHomeCredentials() {
		fail("Not yet implemented");
	}

	//@Test
	public void testLoginListOfAAMHomeCredentials() {
		fail("Not yet implemented");
	}

	//@Test
	public void testLoginAsGuest() {
		fail("Not yet implemented");
	}

	//@Test
	public void testValidate() {
		fail("Not yet implemented");
	}

	
	public AAM getHomeAMM() throws Throwable 
	{

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
	
	public String getCertString(String keystoreFilename, String spassword, String alias ) throws Throwable 
	{
		
		String result=null;
		
		char[] password = spassword.toCharArray();
	    
	    FileInputStream fIn = new FileInputStream(keystoreFilename);
	    KeyStore keystore = KeyStore.getInstance("JKS");
	    	    
	    //Leer
		keystore.load(fIn, password);
		java.security.cert.Certificate cert = keystore.getCertificate(alias);
		System.out.println("cert:");
		System.out.println("keystoreFilename: "+keystoreFilename);
		System.out.println("spassword: "+spassword);
		System.out.println("alias: "+alias);
		System.out.println(cert);

		
		result = CryptoHelper.convertX509ToPEM((X509Certificate)cert);
		
		return result;
	}
	
	public void deletekeystore() throws Throwable 
	{
		logger.info("deletekeystore()");		
		FileInputStream fIn = new FileInputStream(keystorePath);
	    KeyStore keystore = KeyStore.getInstance("JKS");
		char[] password = skeystorePassword.toCharArray();
	    keystore.load(fIn, password);
	    
	    Enumeration<String> aliasList = keystore.aliases();
	    
	    while(aliasList.hasMoreElements()) 
	    {
	    	String alias = aliasList.nextElement();
	    	keystore.deleteEntry(alias);
	    	logger.info("alias: [" + alias + "] deleted");
	    }

	    FileOutputStream fOut = new FileOutputStream(keystorePath);
	    keystore.store(fOut, password);

		logger.info( keystorePath + " empty");		
		
	}
	
	
	public Map<String, AAM> getAMMList() throws Throwable 
	{
		Map<String, AAM> aamMap = new HashMap<>();
	    Certificate certificate = new Certificate();
		
		for(int i=0; i<3; i++)
		{
			String key = "ammId"+i;
		    String aamAddress = "https:\\www.aamserver"+i;
		    String aamInstanceFriendlyName = "name-friendly-xxx"+i;
			String aamInstanceId = "id-instance-123"+i;
			AAM value = new AAM(aamAddress, aamInstanceFriendlyName, aamInstanceId, certificate);
			aamMap.put(key, value);
		}
		
		return aamMap;
	}

	
}
