package eu.h2020.symbiote.security.helpers.accesspolicies;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.BooleanAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.CompositeAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.NumericAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.StringAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
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
 * Created by Nemanja on 05.02.2018.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */

public class ABACPolicyHelperAttributeOrientedAccessPoliciesTest {

    private static final String ISSUING_AAM_CERTIFICATE_ALIAS = "core-1";
    private static final String CLIENT_CERTIFICATE_ALIAS = "client-core-1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/core.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private final String username = "testusername";
    private final String clientId = "testclientid";
    private final String deploymentId = "deploymentId";

    private final String goodResourceID = "goodResourceID";
    private final String goodResourceID2 = "goodResourceID2";
    private final String badResourceID = "badResourceID";
    private final String badResourceID2 = "badResourceID2";

    private final String fromEUAttr = "fromEU";
    private final String nameAttr = "name";
    private final String ageAttr = "age";
    private final String missingAttr = "youAreGonnaMissMe";

    private final String fromEUAttrOKValue = "false";
    private final String fromEUAttrBadValue = "true";
    private final String nameAttrOKValue = "John";
    private final String nameAttrBadValue = "Mike";
    private final Integer ageAttrOKValue = 20;
    private final Integer ageAttrBadValue = 33;

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
        attributes.put(ageAttr, String.valueOf(ageAttrOKValue));
        attributes.put(fromEUAttr, fromEUAttrOKValue);

        String authorizationToken = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributes,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                deploymentId,
                issuingAAMPublicKey,
                issuingAAMPrivateKey, DummyTokenIssuer.SignatureType.PROPER);

        AuthorizationCredentials authorizationCredentials = new AuthorizationCredentials(new Token(authorizationToken), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsSet.add(authorizationCredentials);


        Map<String, String> attributesFirst = new HashMap<>();
        attributes.put(nameAttr, nameAttrOKValue);

        Map<String, String> attributesSecond = new HashMap<>();
        attributes.put(ageAttr, String.valueOf(ageAttrOKValue));

        String authorizationTokenOne = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributesFirst,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                deploymentId,
                issuingAAMPublicKey,
                issuingAAMPrivateKey, DummyTokenIssuer.SignatureType.PROPER);

        String authorizationTokenTwo = DummyTokenIssuer.buildAuthorizationToken(clientId,
                attributesSecond,
                clientPublicKey.getEncoded(),
                Token.Type.HOME,
                (long) (36000000),
                deploymentId,
                issuingAAMPublicKey,
                issuingAAMPrivateKey, DummyTokenIssuer.SignatureType.PROPER);

        AuthorizationCredentials authorizationCredentialsFirst = new AuthorizationCredentials(new Token(authorizationTokenOne), homeCredentials.homeAAM, homeCredentials);
        AuthorizationCredentials authorizationCredentialsSecond = new AuthorizationCredentials(new Token(authorizationTokenTwo), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsMultipleTokensSet.add(authorizationCredentialsFirst);
        this.authorizationCredentialsMultipleTokensSet.add(authorizationCredentialsSecond);
    }

    @Test
    public void singleNumberAccessRuleEqualsCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleNotEqualsCheckSuccess() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.NOT_EQUALS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleNotEqualsCheckFailure() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.NOT_EQUALS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleGreaterThanCheckSuccess() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue-1, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.GREATER_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleGreaterThanCheckFailure() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();
        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.GREATER_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleLessThanCheckSuccess() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue+1, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.LESS_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleLessThanCheckFailure() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.LESS_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleGreaterOrEqualsCheckSuccess() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.GREATER_OR_EQUAL_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleGreaterOrEqualsCheckFailure() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue+1, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.GREATER_OR_EQUAL_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleLessOrEqualsCheckSuccess() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.LESS_OR_EQUALS_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleNumberAccessRuleLessOrEqualsCheckFailure() throws NoSuchAlgorithmException, InvalidArgumentsException{
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue-1, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.LESS_OR_EQUALS_THAN);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleBooleanAccessRuleFalseValueCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(booleanAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleBooleanAccessRuleFalseValueCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(booleanAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(!resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleStringAccessRuleCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleEqualsIgnoreCaseCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue.toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleEqualsIgnoreCaseCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrBadValue.toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleContainsCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue+" Meyer", SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.CONTAINS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleContainsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrBadValue+" Doe", SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.CONTAINS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleContainsIgnoreCaseCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrOKValue+" Doe").toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.CONTAINS_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleContainsIgnoreCaseCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrBadValue+" Doe").toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.CONTAINS_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleStringAccessRuleNotContainsCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrBadValue+" Doe", SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.NOT_CONTAINS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleNotContainsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue+" Doe", SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.NOT_CONTAINS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleNotContainsIgnoreCaseCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrBadValue+" Doe").toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.NOT_CONTAINS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleNotContainsIgnoreCaseCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrOKValue + " Doe").toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.NOT_CONTAINS_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleStartsWithCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrOKValue.substring(0,1)), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.STARTS_WITH);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleStartsWithCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrBadValue.substring(0,1)), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.STARTS_WITH);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleStringAccessRuleStartsWithIgnoreCaseCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrOKValue.substring(0,2)).toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.STARTS_WITH_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleStartsWithIgnoreCaseCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrBadValue.substring(0,2)).toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.STARTS_WITH_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleEndsWithCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrOKValue.substring(nameAttrOKValue.length() - 2, nameAttrOKValue.length())), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.ENDS_WITH);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singleStringAccessRuleEndsWithCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrBadValue.substring(nameAttrOKValue.length()-2,nameAttrOKValue.length()-1)), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.ENDS_WITH);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleStringAccessRuleEndsWithIgnoreCaseCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrOKValue.substring(nameAttrOKValue.length() - 1, nameAttrOKValue.length())).toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.ENDS_WITH_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void singleStringAccessRuleEndsWithIgnoreCaseCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule((nameAttrBadValue.substring(nameAttrOKValue.length() - 1, nameAttrOKValue.length())).toUpperCase(), SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.ENDS_WITH_IGNORE_CASE);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositeAccessRuleCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        NumericAccessRule numAccessRule = new NumericAccessRule(18, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.GREATER_THAN);

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        Set<IAccessRule> arSet1 = new HashSet<>();
        arSet1.add(stringAccessRule);
        arSet1.add(booleanAccessRule);

        CompositeAccessRule compositeAR1 = new CompositeAccessRule(arSet1, CompositeAccessRule.CompositeAccessRulesOperator.OR);

        Set<IAccessRule> arSet2 = new HashSet<>();
        arSet2.add(compositeAR1);
        arSet2.add(numAccessRule);

        CompositeAccessRule compositeAR2 = new CompositeAccessRule(arSet2, CompositeAccessRule.CompositeAccessRulesOperator.AND);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new AttributeOrientedAccessPolicySpecifier(compositeAR2)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

}