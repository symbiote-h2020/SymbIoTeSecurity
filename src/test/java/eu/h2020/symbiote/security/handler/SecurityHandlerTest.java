package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.clients.AAMClient;
import eu.h2020.symbiote.security.clients.ClientFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.fail;


@RunWith(PowerMockRunner.class)
public class SecurityHandlerTest {
	
	
	private AAMClient aamClient = Mockito.mock(AAMClient.class);
	
	private static Log logger = LogFactory.getLog(SecurityHandlerTest.class);
	SecurityHandler client = null;

	@Before
	public void prepare() throws SecurityHandlerException {
		
		PowerMockito.mockStatic(ClientFactory.class);
		
		Mockito.when(ClientFactory.getAAMClient(Matchers.anyString())).thenReturn(aamClient);
		
		Mockito.when(aamClient.getClientCertificate(Mockito.any(CertificateRequest.class))).thenReturn("Certificated");
		
		AvailableAAMsCollection listAAMs = Mockito.mock(AvailableAAMsCollection.class);
		
		Map<String, AAM> aamMap = new HashMap<>();
		
		Mockito.when(listAAMs.getAvailableAAMs()).thenReturn(aamMap);
		
		Mockito.when(aamClient.getAvailableAAMs()).thenReturn(listAAMs);
  
		
		String scoreAAMAddress ="";
	    String skeystorePassword = "123456";
	    String sclientId = "sym1";
	    boolean bisOnline = false;
	    
	    //client = new AbstractSecurityHandler(skeystorePassword, sclientId, bisOnline);

	}

	@Test
	public void testGetCertificate() throws SecurityHandlerException {
		
		logger.info("testGetCertificate starts");
					
		Certificate cer = client.getCertificate(getHomeAMM(), "usu1", "pass1", "clientID");

		logger.info("TEST RESULT --> Certificate from AMM: " + cer);
		assert cer != null;
//		assert cer.equalsIgnoreCase("Monitoring message received in CRM");		

				
//		String message = client.doPost2CrmTest(getTestPlatform(), "myTestToken");
//		logger.info("TEST RESULT --> Message from CRM: " + message);
//		assert message != null;
//		assert message.equalsIgnoreCase("Monitoring message received in CRM");		
		
		
		//fail("Not yet implemented");
	
	}


	@Test
	public void testClearCachedTokens() {
		fail("Not yet implemented");
	}

	@Test
	public void testGetAvailableAAMs() {
		fail("Not yet implemented");
	}

	@Test
	public void testLoginHomeCredentials() {
		fail("Not yet implemented");
	}

	@Test
	public void testLoginListOfAAMHomeCredentials() {
		fail("Not yet implemented");
	}

	@Test
	public void testLoginAsGuest() {
		fail("Not yet implemented");
	}

	@Test
	public void testValidate() {
		fail("Not yet implemented");
	}

	
	public AAM getHomeAMM() 
	{
		String aamInstanceId = "";
	    String aamAddress = "";
	    String aamInstanceFriendlyName = "";
	    Certificate certificate;
	    
	    certificate = new Certificate();
	    
	    AAM home = new AAM(aamInstanceId, aamAddress, aamInstanceFriendlyName, certificate);
	    
	    return home;
	    
	}
	
	
}
