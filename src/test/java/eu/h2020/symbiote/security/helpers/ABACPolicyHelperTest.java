package eu.h2020.symbiote.security.helpers;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.SingleTokenAccessPolicy;
import eu.h2020.symbiote.security.commons.*;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.MalformedJWTException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.ABACResolverResponse;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.utils.DummyTokenIssuer;
import org.junit.Before;
import org.junit.Test;

import java.io.FileInputStream;
import java.security.*;
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

public class ABACPolicyHelperTest {

    private static final String ISSUING_AAM_CERTIFICATE_ALIAS = "core-1";
    private static final String CLIENT_CERTIFICATE_ALIAS = "client-core-1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/core.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private static final String SERVICE_CERTIFICATE_ALIAS = "platform-1-1-c1"; // let's suppose it
    private static final String SERVICE_CERTIFICATE_LOCATION = "./src/test/resources/platform_1.p12"; // let's suppose it
    private final String username = "testusername";
    private final String clientId = "testclientid";
    private HashSet<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<>();
    private HashSet<AuthorizationCredentials> authorizationCredentialsMultipleTokensSet = new HashSet<>();

    private final String deploymentId = "deploymentId";

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
        HomeCredentials homeCredentials = new HomeCredentials(issuingAAM, username, clientId, new eu.h2020.symbiote.security.commons.Certificate(CryptoHelper.convertX509ToPEM(clientCertificate)), clientPrivateKey);

        Map<String, String> attributes = new HashMap<String, String>();
        attributes.put(nameAttr, nameAttrOKValue);
        attributes.put(ageAttr, ageAttrOKValue);

        String authorizationToken = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributes,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                deploymentId,
                issuingAAMPublicKey,
                issuingAAMPrivateKey);

        AuthorizationCredentials authorizationCredentials = new AuthorizationCredentials(new Token(authorizationToken), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsSet.add(authorizationCredentials);


        Map<String, String> attributesFirst = new HashMap<String, String>();
        attributes.put(nameAttr, nameAttrOKValue);

        Map<String, String> attributesSecond = new HashMap<String, String>();
        attributes.put(ageAttr, ageAttrOKValue);

        String authorizationTokenOne = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributesFirst,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
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

        AuthorizationCredentials authorizationCredentialsFirst = new AuthorizationCredentials(new Token(authorizationTokenOne), homeCredentials.homeAAM, homeCredentials);
        AuthorizationCredentials authorizationCredentialsSecond = new AuthorizationCredentials(new Token(authorizationTokenTwo), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsMultipleTokensSet.add(authorizationCredentialsFirst);
        this.authorizationCredentialsMultipleTokensSet.add(authorizationCredentialsSecond);


    }

    @Test
    public void singleResourceSingleTokenCheckSuccess() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> accessPolicyClaimsMap = new HashMap<String, String>();
        accessPolicyClaimsMap.put(nameAttr, nameAttrOKValue);
        accessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);

        resourceAccessPolicyMap.put(goodResourceID, new SingleTokenAccessPolicy(accessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.getAvailableResources().contains(goodResourceID));
    }

    @Test
    public void singleResourceSingleTokenCheckFailure() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> accessPolicyClaimsMap = new HashMap<String, String>();
        accessPolicyClaimsMap.put(nameAttr, nameAttrBadValue);
        accessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);

        resourceAccessPolicyMap.put(badResourceID, new SingleTokenAccessPolicy(accessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.getAvailableResources().contains(badResourceID));

    }

    @Test
    public void singleResourceSingleTokenMissingAttribute() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> accessPolicyClaimsMap = new HashMap<String, String>();
        accessPolicyClaimsMap.put(nameAttr, nameAttrBadValue);
        accessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);
        accessPolicyClaimsMap.put(missingAttr, "");

        resourceAccessPolicyMap.put(badResourceID, new SingleTokenAccessPolicy(accessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.getAvailableResources().contains(badResourceID));

    }

    @Test
    public void multipleResourceSingleTokenCheckOneSuccessOneFailure() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> goodResourceAccessPolicyClaimsMap = new HashMap<String, String>();
        goodResourceAccessPolicyClaimsMap.put(nameAttr, nameAttrOKValue);
        goodResourceAccessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);


        resourceAccessPolicyMap.put(goodResourceID, new SingleTokenAccessPolicy(goodResourceAccessPolicyClaimsMap));

        Map<String, String> badResourceAccessPolicyClaimsMap = new HashMap<String, String>();
        badResourceAccessPolicyClaimsMap.put(nameAttr, nameAttrBadValue);
        badResourceAccessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);
        resourceAccessPolicyMap.put(badResourceID, new SingleTokenAccessPolicy(badResourceAccessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.getAvailableResources().contains(goodResourceID));
        assertFalse(resp.getAvailableResources().contains(badResourceID));

    }

    @Test
    public void multipleResourceSingleTokenAllSuccess() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> goodResourceAccessPolicyClaimsMap = new HashMap<String, String>();
        goodResourceAccessPolicyClaimsMap.put(nameAttr, nameAttrOKValue);
        goodResourceAccessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);


        resourceAccessPolicyMap.put(goodResourceID, new SingleTokenAccessPolicy(goodResourceAccessPolicyClaimsMap));

        Map<String, String> badResourceAccessPolicyClaimsMap = new HashMap<String, String>();
        badResourceAccessPolicyClaimsMap.put(nameAttr, nameAttrOKValue);
        badResourceAccessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);
        resourceAccessPolicyMap.put(goodResourceID2, new SingleTokenAccessPolicy(badResourceAccessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.getAvailableResources().contains(goodResourceID));
        assertTrue(resp.getAvailableResources().contains(goodResourceID2));

    }

    @Test
    public void multipleResourceSingleTokenAllFailure() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> goodResourceAccessPolicyClaimsMap = new HashMap<String, String>();
        goodResourceAccessPolicyClaimsMap.put(nameAttr, nameAttrBadValue);
        goodResourceAccessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);


        resourceAccessPolicyMap.put(badResourceID, new SingleTokenAccessPolicy(goodResourceAccessPolicyClaimsMap));

        Map<String, String> badResourceAccessPolicyClaimsMap = new HashMap<String, String>();
        badResourceAccessPolicyClaimsMap.put(nameAttr, nameAttrBadValue);
        badResourceAccessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);
        resourceAccessPolicyMap.put(badResourceID2, new SingleTokenAccessPolicy(badResourceAccessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.getAvailableResources().contains(badResourceID));
        assertFalse(resp.getAvailableResources().contains(badResourceID2));

    }

    @Test
    public void singleResourceMultipleTokensSuccess() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> accessPolicyClaimsMap = new HashMap<String, String>();
        accessPolicyClaimsMap.put(nameAttr, nameAttrOKValue);
        accessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);

        resourceAccessPolicyMap.put(goodResourceID, new SingleTokenAccessPolicy(accessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);
        //TODO Nemanja check if attribtues accumulation for access policy should be supported, then uncomment
        //assertTrue(allowedResources.contains(goodResourceID));

    }

    @Test
    public void singleResourceMultipleTokensFailure() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();
        Map<String, String> accessPolicyClaimsMap = new HashMap<String, String>();
        accessPolicyClaimsMap.put(nameAttr, nameAttrBadValue);
        accessPolicyClaimsMap.put(ageAttr, ageAttrOKValue);

        resourceAccessPolicyMap.put(badResourceID, new SingleTokenAccessPolicy(accessPolicyClaimsMap));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);


        assertFalse(resp.getAvailableResources().contains(badResourceID));

    }

    @Test
    public void singleResourceEmptyPolicySuccess() throws NoSuchAlgorithmException, MalformedJWTException, SecurityHandlerException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<String, IAccessPolicy>();

        resourceAccessPolicyMap.put(goodResourceID, new SingleTokenAccessPolicy(null));

        ABACResolverResponse resp = ABACPolicyHelper.checkRequestedOperationAccess(deploymentId, resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.getAvailableResources().contains(goodResourceID));

    }
}