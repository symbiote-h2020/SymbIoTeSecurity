package eu.h2020.symbiote.security.helpers.accesspolicies;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyFactory;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.BooleanAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.CompositeAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.NumericAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.StringAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.CompositePlatformAttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.PlatformAttributeOrientedAccessPolicySpecifier;
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
 * Created by Kaspar on 07.08.2018.
 *
 * @author Kaspar Lebloch (UNIVIE)
 */

public class ABACPolicyHelperPlatformAttributeOrientedAccessPoliciesTest {

    private static final String ISSUING_AAM_CERTIFICATE_ALIAS = "core-1";
    private static final String CLIENT_CERTIFICATE_ALIAS = "client-core-1";
    private static final String CERTIFICATE_LOCATION = "./src/test/resources/core.p12";
    private static final String CERTIFICATE_PASSWORD = "1234567";
    private final String username = "testusername";
    private final String clientId = "testclientid";
    private final String deploymentId = "deploymentId";
    private final String deploymentId2 = "deploymentId2";

    private final String goodResourceID = "goodResourceID";
    private final String goodResourceID2 = "goodResourceID2";
    private final String badResourceID = "badResourceID";
    private final String badResourceID2 = "badResourceID2";

    private final String fromEUAttr = "fromEU";
    private final String nameAttr = "name";
    private final String ageAttr = "age";
    private final String isMaleAttr = "isMale";

    private final String missingAttr = "youAreGonnaMissMe";

    private final String fromEUAttrOKValue = "false";
    private final String fromEUAttrBadValue = "true";
    private final String nameAttrOKValue = "John";
    private final String nameAttrBadValue = "Mike";
    private final Integer ageAttrOKValue = 20;
    private final Integer ageAttrBadValue = 33;
    private final String isMaleOKValue = "true";

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
                issuingAAMPrivateKey);

        AuthorizationCredentials authorizationCredentials = new AuthorizationCredentials(new Token(authorizationToken), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsSet.add(authorizationCredentials);


        Map<String, String> attributesFirst = new HashMap<>();
        attributesFirst.put(nameAttr, nameAttrOKValue);
        attributesFirst.put(ageAttr, String.valueOf(ageAttrOKValue));

        Map<String, String> attributesSecond = new HashMap<>();
        attributesSecond.put(fromEUAttr, fromEUAttrOKValue);
        attributesSecond.put(isMaleAttr, String.valueOf(isMaleOKValue));

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
                deploymentId2,
                issuingAAMPublicKey,
                issuingAAMPrivateKey);

        AuthorizationCredentials authorizationCredentialsFirst = new AuthorizationCredentials(new Token(authorizationTokenOne), homeCredentials.homeAAM, homeCredentials);
        AuthorizationCredentials authorizationCredentialsSecond = new AuthorizationCredentials(new Token(authorizationTokenTwo), homeCredentials.homeAAM, homeCredentials);
        this.authorizationCredentialsMultipleTokensSet.add(authorizationCredentialsFirst);
        this.authorizationCredentialsMultipleTokensSet.add(authorizationCredentialsSecond);
    }

    @Test
    public void singlePAOAPNumberAccessRuleEqualsCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPNumberAccessRuleNotEqualsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.NOT_EQUALS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPNumberAccessRuleWrongPlatformCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.NOT_EQUALS);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId+"123",numAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPStringAccessRuleEqualsCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPStringAccessRuleNotContainsCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.NOT_CONTAINS);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPStringAccessRuleWrongPlatformCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId+"123",stringAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPBooleanAccessRuleIsTrueCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2,booleanAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPBooleanAccessRuleIsTrueCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,booleanAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPBooleanAccessRuleWrongPlatformCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId + "123",booleanAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPCompositeAccessRuleCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue,SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);
        Set<IAccessRule> accessRules = new HashSet<>();
        accessRules.add(booleanAccessRule);
        accessRules.add(stringAccessRule);
        CompositeAccessRule compositeAccessRule = new CompositeAccessRule(accessRules,CompositeAccessRule.CompositeAccessRulesOperator.AND);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,compositeAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPCompositeAccessRuleCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue,SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);
        Set<IAccessRule> accessRules = new HashSet<>();
        accessRules.add(booleanAccessRule);
        accessRules.add(stringAccessRule);
        CompositeAccessRule compositeAccessRule = new CompositeAccessRule(accessRules,CompositeAccessRule.CompositeAccessRulesOperator.AND);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,compositeAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void singlePAOAPCompositeAccessRuleWrongPlatformCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {
        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue,SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);
        Set<IAccessRule> accessRules = new HashSet<>();
        accessRules.add(booleanAccessRule);
        accessRules.add(stringAccessRule);
        CompositeAccessRule compositeAccessRule = new CompositeAccessRule(accessRules,CompositeAccessRule.CompositeAccessRulesOperator.AND);
        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId +"123",compositeAccessRule)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPSinglePAOPAsANDOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2,booleanAccessRule);
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet = new HashSet<>();
        paoapsSet.add(paoapSpec1);
        paoapsSet.add(paoapSpec2);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet,null)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPSinglePAOPAsANDOperatorCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2,booleanAccessRule);
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet = new HashSet<>();
        paoapsSet.add(paoapSpec1);
        paoapsSet.add(paoapSpec2);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet,null)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPSinglePAOPAsOROperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2,booleanAccessRule);
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet = new HashSet<>();
        paoapsSet.add(paoapSpec1);
        paoapsSet.add(paoapSpec2);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,paoapsSet,null)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPSinglePAOPAsOROperatorCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId,numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2,booleanAccessRule);
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet = new HashSet<>();
        paoapsSet.add(paoapSpec1);
        paoapsSet.add(paoapSpec2);

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,paoapsSet,null)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPCompositePAOPAsANDOperatorCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);

        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,null, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void compositePAOAPCompositePAOPAsANDOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);

        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,null, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPCompositePAOPAsOROperatorCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);

        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,null, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPCompositePAOPAsOROperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);

        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,null, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPSingleAndCompositePAOPAsANDOperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet3 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);
        paoapsSet3.add(paoapSpec1);


        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet3, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPSingleAndCompositePAOPAsANDOperatorCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet3 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);
        paoapsSet3.add(paoapSpec1);


        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet3, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }


    @Test
    public void compositePAOAPSingleAndCompositePAOPAsOROperatorCheckSuccess() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet3 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);
        paoapsSet3.add(paoapSpec1);


        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,paoapsSet3, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertTrue(resp.keySet().contains(goodResourceID));
    }

    @Test
    public void compositePAOAPSingleAndCompositePAOPAsOROperatorCheckFailure() throws
            NoSuchAlgorithmException,
            InvalidArgumentsException,
            ValidationException {

        SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(this.authorizationCredentialsMultipleTokensSet, false);
        assertFalse(securityRequest.getSecurityCredentials().isEmpty());

        Map<String, IAccessPolicy> resourceAccessPolicyMap = new HashMap<>();

        NumericAccessRule numAccessRule = new NumericAccessRule(ageAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.EQUALS);
        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + isMaleAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        BooleanAccessRule booleanAccessRule2 = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_FALSE);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrBadValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec1 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, numAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec2 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec3 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId2, booleanAccessRule2);
        PlatformAttributeOrientedAccessPolicySpecifier paoapSpec4 = new PlatformAttributeOrientedAccessPolicySpecifier(deploymentId, stringAccessRule);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet1 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet2 = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> paoapsSet3 = new HashSet<>();

        paoapsSet1.add(paoapSpec1);
        paoapsSet1.add(paoapSpec2);
        paoapsSet2.add(paoapSpec3);
        paoapsSet2.add(paoapSpec4);
        paoapsSet3.add(paoapSpec1);


        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoapSet = new HashSet<>();

        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet1, null));
        cpaoapSet.add(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,paoapsSet2, null));

        resourceAccessPolicyMap.put(goodResourceID, AccessPolicyFactory.getAccessPolicy(new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR,paoapsSet3, cpaoapSet)));

        Map<String, Set<SecurityCredentials>> resp = ABACPolicyHelper.checkRequestedOperationAccess(resourceAccessPolicyMap, securityRequest);

        assertFalse(resp.keySet().contains(goodResourceID));
    }

}