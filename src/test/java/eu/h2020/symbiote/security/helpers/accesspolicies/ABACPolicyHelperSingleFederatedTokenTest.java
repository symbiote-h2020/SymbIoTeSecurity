package eu.h2020.symbiote.security.helpers.accesspolicies;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.helpers.ABACPolicyHelper;
import eu.h2020.symbiote.security.helpers.CryptoHelper;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by Nemanja on 22.08.2017.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */

public class ABACPolicyHelperSingleFederatedTokenTest {

    private static final String ISSUING_AAM_CERTIFICATE_ALIAS = "core-1";
    private static final String CLIENT_CERTIFICATE_ALIAS = "client-core-1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/core.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private final String username = "testusername";
    private final String clientId = "testclientid";
    private final String deploymentId = "deploymentId";
    private final String federationId = "federationId";
    private final String federationId2 = "federationId2";
    private final String federatedPlatformId = "federatedPlatfomrId";

    private final String goodResourceID = "goodResourceID";
    private final String goodResourceID2 = "goodResourceID2";
    private final String badResourceID = "badResourceID";
    private final String badResourceID2 = "badResourceID2";

    private final String nameAttr = "name";
    private final String ageAttr = "age";
    private final String missingAttr = "youAreGonnaMissMe";

    private final String nameAttrOKValue = "John";
    private final String nameAttrBadValue = "Mike";
    private final String ageAttrOKValue = "20";

    private HashSet<AuthorizationCredentials> authorizationCredentialsForeignTokenSet = new HashSet<>();
    private HashSet<AuthorizationCredentials> authorizationCredentialsHomeTokenSet = new HashSet<>();

    @Before
    public void setUp() throws Exception {
        ECDSAHelper.enableECDSAProvider();

        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(new FileInputStream(CERTIFICATE_LOCATION), CERTIFICATE_PASSWORD.toCharArray());

        // issuing AAM platform (core-1 in this case)
        X509Certificate issuingAAMCertificate = (X509Certificate) ks.getCertificate(ISSUING_AAM_CERTIFICATE_ALIAS);
        PublicKey issuingAAMPublicKey = issuingAAMCertificate.getPublicKey();
        PrivateKey issuingAAMPrivateKey = (PrivateKey) ks.getKey(ISSUING_AAM_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

        // client
        X509Certificate clientCertificate = (X509Certificate) ks.getCertificate(CLIENT_CERTIFICATE_ALIAS);
        PublicKey clientPublicKey = clientCertificate.getPublicKey();
        PrivateKey clientPrivateKey = (PrivateKey) ks.getKey(CLIENT_CERTIFICATE_ALIAS, CERTIFICATE_PASSWORD.toCharArray());

        // client home credentials
        AAM issuingAAM = new AAM("", "", "", new Certificate(CryptoHelper.convertX509ToPEM(issuingAAMCertificate)), new HashMap<>());
        HomeCredentials homeCredentials = new HomeCredentials(issuingAAM, username, clientId, new Certificate(CryptoHelper.convertX509ToPEM(clientCertificate)), clientPrivateKey);

        Map<String, String> attributesFirst = new HashMap<>();
        attributesFirst.put("federation_1", federationId);
        Map<String, String> attributesSecond = new HashMap<>();
        attributesSecond.put("federation_1", federationId);

        String authorizationTokenOne = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributesFirst,
                clientPublicKey.getEncoded(),
                Token.Type.FOREIGN,
                (long) (36000000),
                federatedPlatformId,
                issuingAAMPublicKey,
                issuingAAMPrivateKey);

        String authorizationTokenTwo = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributesSecond,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                deploymentId,
                issuingAAMPublicKey,
                issuingAAMPrivateKey);

        AuthorizationCredentials authorizationCredentialsFirst = new AuthorizationCredentials(new Token(authorizationTokenOne), homeCredentials.homeAAM, homeCredentials);
        AuthorizationCredentials authorizationCredentialsSecond = new AuthorizationCredentials(new Token(authorizationTokenTwo), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsForeignTokenSet.add(authorizationCredentialsFirst);
        this.authorizationCredentialsHomeTokenSet.add(authorizationCredentialsSecond);


    }

    @Test
    public void singleResourceSingleTokenCheckSuccess() throws
            NoSuchAlgorithmException,
            MalformedJWTException,
            SecurityHandlerException,
            InvalidArgumentsException {

        Set<String> federationMembers = new HashSet<>();
        federationMembers.add(federatedPlatformId);
        federationMembers.add(deploymentId);

        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(federationMembers, deploymentId, federationId);

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        resourceAccessPolicyMap.put(goodResourceID, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));

        //check security request with proper foreign token
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsForeignTokenSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());
        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);
        assertTrue(resp.keySet().contains(goodResourceID));

        //check security request with proper HOME token
        securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsHomeTokenSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());
        resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);
        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceSingleTokenCheckFailWrongFederationId() throws
            NoSuchAlgorithmException,
            MalformedJWTException,
            SecurityHandlerException,
            InvalidArgumentsException {

        Set<String> federationMembers = new HashSet<>();
        federationMembers.add(deploymentId);

        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(federationMembers, deploymentId, federationId2);

        //check security request with foreign token without proper federation attribute
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsForeignTokenSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        resourceAccessPolicyMap.put(goodResourceID, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);
        assertFalse(resp.keySet().contains(goodResourceID));
    }
}