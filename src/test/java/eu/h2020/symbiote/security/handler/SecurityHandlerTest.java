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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.fail;


@RunWith(PowerMockRunner.class)
@PrepareForTest(ClientFactory.class)
public class SecurityHandlerTest {
	
	
	private AAMClient aamClient = Mockito.mock(AAMClient.class);
	
	private static Log logger = LogFactory.getLog(SecurityHandlerTest.class);
	SecurityHandler client = null;

    String keystorePath = "./src/test/resources/keystore.jks";
    String skeystorePassword = "123456";
    boolean bisOnline = false;
    
	String TestkeystorePath= "./src/test/resources/core.p12";
    String TestkeystorePassword = "1234567";
    String Testalias = "client-core-1";
    
	@Before
	public void prepare() throws SecurityHandlerException {
		
		PowerMockito.mockStatic(ClientFactory.class);
		
		Mockito.when(ClientFactory.getAAMClient(Matchers.anyString())).thenReturn(aamClient);
		
		Mockito.when(aamClient.getClientCertificate(Mockito.any(CertificateRequest.class))).thenReturn("Certificated");
		
		AvailableAAMsCollection listAAMs = Mockito.mock(AvailableAAMsCollection.class);
		
		Map<String, AAM> aamMap = new HashMap<>();
		
		Mockito.when(listAAMs.getAvailableAAMs()).thenReturn(aamMap);
		
		Mockito.when(aamClient.getAvailableAAMs()).thenReturn(listAAMs);
  
			    
	    client = new SecurityHandler(keystorePath, skeystorePassword, bisOnline);

	}

	@Test
	public void testGetCertificate() throws Throwable {
		
		logger.info("testGetCertificate starts");
		
		String TestkeystorePath= "./src/test/resources/core.p12";
	    char[] TestkeystorePassword = "1234567".toCharArray();
	    String alias = "client-core-1";
					
		Certificate cer = client.getCertificate(getHomeAMM(), "usu1", "pass1", "clientID");

		logger.info("TEST RESULT --> Certificate from AMM: " + cer);
		assert cer != null;	
		assert (cer.getCertificateString()).equalsIgnoreCase(getCertString(keystorePath, skeystorePassword, Testalias ));		

				
//		String message = client.doPost2CrmTest(getTestPlatform(), "myTestToken");
//		logger.info("TEST RESULT --> Message from CRM: " + message);
//		assert message != null;
//		assert message.equalsIgnoreCase("Monitoring message received in CRM");		
		
		
		//fail("Not yet implemented");
	
	}


	//@Test
	public void testClearCachedTokens() {
		fail("Not yet implemented");
	}

	//@Test
	public void testGetAvailableAAMs() {
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
		String aamInstanceId = "id-instance-123";
	    String aamAddress = "https:\\www.aamserver";
	    String aamInstanceFriendlyName = "name-instance-123";
		String pathCert = "./scr/test/resources/core.p12";
		
	    	       
	    InputStream fis = new FileInputStream(pathCert);
	    BufferedInputStream bis = new BufferedInputStream(fis);
	    
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    java.security.cert.Certificate cert = cf.generateCertificate(bis);
	    
	    
	    Certificate certificate = new Certificate();
	    

	    
	    String certificateString = getCertString(TestkeystorePath, TestkeystorePassword, Testalias);
	    
	    certificate.setCertificateString(certificateString);
	      
	    AAM home = new AAM(aamInstanceId, aamAddress, aamInstanceFriendlyName, certificate);
	    
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
		System.out.println(cert);

		CryptoHelper ch = new CryptoHelper();
		
		result = ch.convertX509ToPEM((X509Certificate)cert);
		
		return result;
	}
	
	
}
