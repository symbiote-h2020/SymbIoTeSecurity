package eu.h2020.symbiote.security.helpers.accesspolicies;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.CompositeAccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
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
 * Created by Nemanja on 10.11.2017.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */

public class ABACPolicyHelperCompositeAccessPoliciesTest {

    private static final String ISSUING_AAM_CERTIFICATE_ALIAS = "core-1";
    private static final String CLIENT_CERTIFICATE_ALIAS = "client-core-1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/core.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private final String username = "testusername";
    private final String clientId = "testclientid";
    private final String deploymentId = "deploymentId";

    private final String goodResourceID = "goodResourceID";

    private final String nameAttr = "name";
    private final String ageAttr = "age";

    private final String nameAttrOKValue = "John";
    private final String nameAttrBadValue = "Mike";
    private final String ageAttrOKValue = "20";
    private final String ageAttrBadValue = "33";

    private HashSet<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<>();
    private HashSet<AuthorizationCredentials> authorizationCredentialsMultipleTokensSet = new HashSet<>();

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

        Map<String, String> attributes = new HashMap<>();
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


        Map<String, String> attributesFirst = new HashMap<>();
        attributes.put(nameAttr, nameAttrOKValue);

        Map<String, String> attributesSecond = new HashMap<>();
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
    public void singleResourceMultipleTokensOrOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensOrOperatorOneBadArgumentCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensOrOperatorBadArgumentsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleResourceMultipleTokensAndOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensAndOperatorOneBadArgumentCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensAndOperatorBadArgumentsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }
    @Test
    public void singleResourceMultipleTokensCompositeAndSingleAndOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        Set<SingleTokenAccessPolicySpecifier> singleAccessPolicySet = new HashSet<>();
        singleAccessPolicySet.add(testPolicySpecifierThird);

        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifier);

        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                singleAccessPolicySet, nestedAccessPoliciesSet
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensCompositeAndSingleAndOperatorOneBadArgumentCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        Set<SingleTokenAccessPolicySpecifier> singleAccessPolicySet = new HashSet<>();
        singleAccessPolicySet.add(testPolicySpecifierThird);

        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifier);

        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                singleAccessPolicySet, nestedAccessPoliciesSet
        );
        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensCompositeAndSingleAndOperatorTwoBadArgumentsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        Set<SingleTokenAccessPolicySpecifier> singleAccessPolicySet = new HashSet<>();
        singleAccessPolicySet.add(testPolicySpecifierThird);

        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifier);

        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                singleAccessPolicySet, nestedAccessPoliciesSet
        );
        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensCompositeAndCompositeAndOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Map<String, String> accessPolicyClaimsMapFourth = new HashMap<>();
        accessPolicyClaimsMapFourth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFourth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFourth
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetFirst = new HashSet<>();
        accessPoliciesSetFirst.add(testPolicySpecifierFirst);
        accessPoliciesSetFirst.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifierFirst = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetFirst, null
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSecond = new HashSet<>();
        accessPoliciesSetSecond.add(testPolicySpecifierThird);
        accessPoliciesSetSecond.add(testPolicySpecifierFourth);

        CompositeAccessPolicySpecifier compositePolicySpecifierSecond = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSecond, null
        );


        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifierFirst);
        nestedAccessPoliciesSet.add(compositePolicySpecifierSecond);


        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                null, nestedAccessPoliciesSet
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleResourceMultipleTokensCompositeAndCompositeAndOperatorOneBadArgumentCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Map<String, String> accessPolicyClaimsMapFourth = new HashMap<>();
        accessPolicyClaimsMapFourth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFourth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFourth
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetFirst = new HashSet<>();
        accessPoliciesSetFirst.add(testPolicySpecifierFirst);
        accessPoliciesSetFirst.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifierFirst = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetFirst, null
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSecond = new HashSet<>();
        accessPoliciesSetSecond.add(testPolicySpecifierThird);
        accessPoliciesSetSecond.add(testPolicySpecifierFourth);

        CompositeAccessPolicySpecifier compositePolicySpecifierSecond = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSecond, null
        );


        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifierFirst);
        nestedAccessPoliciesSet.add(compositePolicySpecifierSecond);


        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                null, nestedAccessPoliciesSet
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleResourceThreeTokensAndOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);
        accessPoliciesSet.add(testPolicySpecifierThird);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleResourceThreeTokensAndOperatorOneBadArgumentCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);
        accessPoliciesSet.add(testPolicySpecifierThird);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceThreeTokensOROperatorTwoBadArgumentsCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);
        accessPoliciesSet.add(testPolicySpecifierThird);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceThreeTokensOROperatorThreeBadArgumentsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSet = new HashSet<>();
        accessPoliciesSet.add(testPolicySpecifierFirst);
        accessPoliciesSet.add(testPolicySpecifierSecond);
        accessPoliciesSet.add(testPolicySpecifierThird);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,
                accessPoliciesSet, null
        );

        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(compositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensCompositeAndCompositeAndSingleAndOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Map<String, String> accessPolicyClaimsMapFourth = new HashMap<>();
        accessPolicyClaimsMapFourth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFourth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFourth
        );


        Map<String, String> accessPolicyClaimsMapFifth = new HashMap<>();
        accessPolicyClaimsMapFifth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFifth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFifth
        );
        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingle = new HashSet<>();
        accessPoliciesSetSingle.add(testPolicySpecifierFifth);

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetFirst = new HashSet<>();
        accessPoliciesSetFirst.add(testPolicySpecifierFirst);
        accessPoliciesSetFirst.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifierFirst = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetFirst, null
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSecond = new HashSet<>();
        accessPoliciesSetSecond.add(testPolicySpecifierThird);
        accessPoliciesSetSecond.add(testPolicySpecifierFourth);

        CompositeAccessPolicySpecifier compositePolicySpecifierSecond = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSecond, null
        );


        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifierFirst);
        nestedAccessPoliciesSet.add(compositePolicySpecifierSecond);


        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, nestedAccessPoliciesSet
        );


        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleResourceMultipleTokensCompositeAndCompositeAndSingleAndOperatorBadArgumentInSingleCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Map<String, String> accessPolicyClaimsMapFourth = new HashMap<>();
        accessPolicyClaimsMapFourth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFourth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFourth
        );


        Map<String, String> accessPolicyClaimsMapFifth = new HashMap<>();
        accessPolicyClaimsMapFifth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFifth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFifth
        );
        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingle = new HashSet<>();
        accessPoliciesSetSingle.add(testPolicySpecifierFifth);

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetFirst = new HashSet<>();
        accessPoliciesSetFirst.add(testPolicySpecifierFirst);
        accessPoliciesSetFirst.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifierFirst = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetFirst, null
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSecond = new HashSet<>();
        accessPoliciesSetSecond.add(testPolicySpecifierThird);
        accessPoliciesSetSecond.add(testPolicySpecifierFourth);

        CompositeAccessPolicySpecifier compositePolicySpecifierSecond = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSecond, null
        );


        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifierFirst);
        nestedAccessPoliciesSet.add(compositePolicySpecifierSecond);


        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, nestedAccessPoliciesSet
        );


        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleResourceMultipleTokensCompositeAndCompositeAndSingleAndOperatorOneBadArgumentInFirstCompositeCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        Map<String, String> accessPolicyClaimsMapFirst = new HashMap<>();
        accessPolicyClaimsMapFirst.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, nameAttrBadValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFirst = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFirst
        );

        Map<String, String> accessPolicyClaimsMapSecond = new HashMap<>();
        accessPolicyClaimsMapSecond.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSecond = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSecond
        );

        Map<String, String> accessPolicyClaimsMapThird = new HashMap<>();
        accessPolicyClaimsMapThird.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierThird = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapThird
        );

        Map<String, String> accessPolicyClaimsMapFourth = new HashMap<>();
        accessPolicyClaimsMapFourth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFourth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFourth
        );


        Map<String, String> accessPolicyClaimsMapFifth = new HashMap<>();
        accessPolicyClaimsMapFifth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierFifth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapFifth
        );
        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingle = new HashSet<>();
        accessPoliciesSetSingle.add(testPolicySpecifierFifth);

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetFirst = new HashSet<>();
        accessPoliciesSetFirst.add(testPolicySpecifierFirst);
        accessPoliciesSetFirst.add(testPolicySpecifierSecond);

        CompositeAccessPolicySpecifier compositePolicySpecifierFirst = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetFirst, null
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSecond = new HashSet<>();
        accessPoliciesSetSecond.add(testPolicySpecifierThird);
        accessPoliciesSetSecond.add(testPolicySpecifierFourth);

        CompositeAccessPolicySpecifier compositePolicySpecifierSecond = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSecond, null
        );


        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifierFirst);
        nestedAccessPoliciesSet.add(compositePolicySpecifierSecond);


        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, nestedAccessPoliciesSet
        );


        resourceAccessPolicyMap.put(goodResourceID, CompositeAccessPolicyFactory.getCompositeAccessPolicy(parentCompositePolicySpecifier));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }
}