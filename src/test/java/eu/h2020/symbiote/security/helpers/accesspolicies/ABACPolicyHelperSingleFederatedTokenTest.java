package eu.h2020.symbiote.security.helpers.accesspolicies;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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

    private HashSet<AuthorizationCredentials> authorizationCredentialsForeignTokenSet = new HashSet<>();
    private HashSet<AuthorizationCredentials> authorizationCredentialsHomeTokenSet = new HashSet<>();
    private HashSet<AuthorizationCredentials> authorizationCredentialsPlatformHomeTokenSet = new HashSet<>();

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

        String authorizationTokenOne = DummyTokenIssuer.buildAuthorizationToken(clientId + "@" + federatedPlatformId,
                attributesFirst,
                clientPublicKey.getEncoded(),
                Token.Type.FOREIGN,
                (long) (36000000),
                deploymentId,
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

        String authorizationTokenThree = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributesSecond,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                federatedPlatformId,
                issuingAAMPublicKey,
                issuingAAMPrivateKey);

        AuthorizationCredentials authorizationCredentialsFirst = new AuthorizationCredentials(new Token(authorizationTokenOne), homeCredentials.homeAAM, homeCredentials);
        AuthorizationCredentials authorizationCredentialsSecond = new AuthorizationCredentials(new Token(authorizationTokenTwo), homeCredentials.homeAAM, homeCredentials);
        AuthorizationCredentials authorizationCredentialsThird = new AuthorizationCredentials(new Token(authorizationTokenThree), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsForeignTokenSet.add(authorizationCredentialsFirst);
        this.authorizationCredentialsHomeTokenSet.add(authorizationCredentialsSecond);
        this.authorizationCredentialsPlatformHomeTokenSet.add(authorizationCredentialsThird);
    }

    @Test
    public void federatedResourceSingleTokenCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        Set<String> federationMembers = new HashSet<>();
        federationMembers.add(federatedPlatformId);
        federationMembers.add(deploymentId);

        //SFTAP
        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(federationId, federationMembers, deploymentId, new HashMap<>(), true);

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
    public void federatedResourceSingleTokenCheckFailWrongFederationId() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        Set<String> federationMembers = new HashSet<>();
        federationMembers.add(deploymentId);

        //SFTAP
        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(federationId2, federationMembers, deploymentId, new HashMap<>(), true);

        //check security request with foreign token without proper federation attribute
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsForeignTokenSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        resourceAccessPolicyMap.put(goodResourceID, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);
        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void federatedResourceSingleHomeTokenCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        Set<String> federationMembers = new HashSet<>();
        federationMembers.add(federatedPlatformId);
        federationMembers.add(deploymentId);

        //SFTAP without Foreign Tokens
        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(federationId, federationMembers, deploymentId, new HashMap<>(), false);

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        resourceAccessPolicyMap.put(goodResourceID, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));

        //check security request with proper HOME token
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsHomeTokenSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());
        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);
        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void federatedResourceSingleHomeTokenCheckFailWrongFederationId() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        Set<String> federationMembers = new HashSet<>();
        federationMembers.add(deploymentId);

        //SFTAP without Foreign Tokens
        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(federationId2, federationMembers, deploymentId, new HashMap<>(), false);

        //check security request with HOME token without proper federation attribute
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsPlatformHomeTokenSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        resourceAccessPolicyMap.put(goodResourceID, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));
        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);
        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void federatedResourceSingleHomeTokenSuccessForLocallyIssuedFederatedToken() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        Set<String> federationMembers = new HashSet<>();
        federationMembers.add(federatedPlatformId);
        federationMembers.add(deploymentId);

        //SFTAP
        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(federationId, federationMembers, deploymentId, new HashMap<>(), true);

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        resourceAccessPolicyMap.put(goodResourceID, SingleTokenAccessPolicyFactory.getSingleTokenAccessPolicy(testPolicySpecifier));

        //check security request with proper HOME token
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsForeignTokenSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());
        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);
        assertTrue(resp.keySet().contains(goodResourceID));
    }
}