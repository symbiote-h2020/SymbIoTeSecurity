package eu.h2020.symbiote.security.helpers.accesspolicies;


import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyJSONDeserializer;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.BooleanAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.CompositeAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.NumericAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.StringAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.CompositePlatformAttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.PlatformAttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.*;

/**
 * Created by Nemanja on 10.11.2017.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Kaspar Lebloch (UNIVIE)
 */

public class ABACPolicyHelperJSONDeserializerTest {


    private final String platformId = "platformId1";
    private final String platformId2 = "platformId2";
    private final String platformId3 = "platformId3";
    private final String nameAttr = "name";
    private final String ageAttr = "age";
    private final String missingAttr = "youAreGonnaMissMe";

    private final String nameAttrOKValue = "John";
    private final String nameAttrBadValue = "Mike";
    private final String ageAttrOKValue = "20";
    private final String ageAttrBadValue = "33";

    private final String fromEUAttr = "fromEU";

    private HashSet<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<>();
    private HashSet<AuthorizationCredentials> authorizationCredentialsMultipleTokensSet = new HashSet<>();

    private JsonFactory jsonFactory;
    private ObjectMapper objMapper;
    private AccessPolicyJSONDeserializer jsonDeserializer;

    @Before
    public void setUp() {
        jsonFactory = new JsonFactory();
        objMapper = new ObjectMapper();

        jsonFactory.setCodec(objMapper);

        jsonDeserializer = new AccessPolicyJSONDeserializer();
    }

    @Test
    public void singleTokensPublicAPDeserialization() throws
            IOException,
            InvalidArgumentsException {

        AccessPolicyType refAPType = AccessPolicyType.PUBLIC;
        Map<String, String> refAPClaimsMapFirst = new HashMap<>();

        SingleTokenAccessPolicySpecifier testPolicySpecifier = new SingleTokenAccessPolicySpecifier(
                refAPType,
                refAPClaimsMapFirst
        );

        String apJson = objMapper.writeValueAsString(testPolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertSingleTokenAPObjectEquality(testPolicySpecifier, deserializedObj);
    }

    @Test
    public void simpleCompositeAccessPolicyAPDeserialization() throws
            IOException,
            InvalidArgumentsException {


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


        String apJson = objMapper.writeValueAsString(compositePolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositeAPObjectEquality(compositePolicySpecifier, deserializedObj);
    }

    @Test
    public void nestedCompositeAccessPolicyAPDeserialization() throws
            IOException,
            InvalidArgumentsException {


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


        String apJson = objMapper.writeValueAsString(parentCompositePolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositeAPObjectEquality(parentCompositePolicySpecifier, deserializedObj);
    }

    @Test
    public void tripleNestedCompositeAccessPolicyAPDeserialization() throws
            IOException,
            InvalidArgumentsException {


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

        Map<String, String> accessPolicyClaimsMapSixth = new HashMap<>();
        accessPolicyClaimsMapSixth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSixth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSixth
        );

        Map<String, String> accessPolicyClaimsMapSeventh = new HashMap<>();
        accessPolicyClaimsMapSeventh.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSeventh = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSeventh
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


        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetThird = new HashSet<>();
        accessPoliciesSetThird.add(testPolicySpecifierSixth);
        accessPoliciesSetThird.add(testPolicySpecifierSeventh);

        CompositeAccessPolicySpecifier compositePolicySpecifierThird = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetThird, null
        );
        //triple nesting
        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifierFirst);
        nestedAccessPoliciesSet.add(compositePolicySpecifierSecond);
        nestedAccessPoliciesSet.add(compositePolicySpecifierThird);

        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, nestedAccessPoliciesSet
        );


        String apJson = objMapper.writeValueAsString(parentCompositePolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositeAPObjectEquality(parentCompositePolicySpecifier, deserializedObj);

    }

    @Test
    public void twoNestedCompositeAccessPolicyAPDeserialization() throws
            IOException, InvalidArgumentsException {


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

        Map<String, String> accessPolicyClaimsMapSixth = new HashMap<>();
        accessPolicyClaimsMapSixth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSixth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSixth
        );

        Map<String, String> accessPolicyClaimsMapSeventh = new HashMap<>();
        accessPolicyClaimsMapSeventh.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierSeventh = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapSeventh
        );

        Map<String, String> accessPolicyClaimsMapEigth = new HashMap<>();
        accessPolicyClaimsMapEigth.put(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, ageAttrOKValue);

        SingleTokenAccessPolicySpecifier testPolicySpecifierEigth = new SingleTokenAccessPolicySpecifier(
                AccessPolicyType.STAP,
                accessPolicyClaimsMapEigth
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingle = new HashSet<>();
        accessPoliciesSetSingle.add(testPolicySpecifierFifth);

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingleSecond = new HashSet<>();
        accessPoliciesSetSingleSecond.add(testPolicySpecifierEigth);

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


        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetThird = new HashSet<>();
        accessPoliciesSetThird.add(testPolicySpecifierSixth);
        accessPoliciesSetThird.add(testPolicySpecifierSeventh);

        CompositeAccessPolicySpecifier compositePolicySpecifierThird = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetThird, null
        );

        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSet = new HashSet<>();
        nestedAccessPoliciesSet.add(compositePolicySpecifierFirst);
        nestedAccessPoliciesSet.add(compositePolicySpecifierSecond);


        Set<CompositeAccessPolicySpecifier> nestedAccessPoliciesSetSecond = new HashSet<>();
        nestedAccessPoliciesSetSecond.add(compositePolicySpecifierThird);

        CompositeAccessPolicySpecifier secondLevelCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingleSecond, nestedAccessPoliciesSetSecond
        );

        CompositeAccessPolicySpecifier secondLevelCompositePolicySpecifierSecond = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, nestedAccessPoliciesSet
        );

        Set<CompositeAccessPolicySpecifier> topLevelCompositePolicySpecifier = new HashSet<>();
        topLevelCompositePolicySpecifier.add(secondLevelCompositePolicySpecifier);
        topLevelCompositePolicySpecifier.add(secondLevelCompositePolicySpecifierSecond);

        CompositeAccessPolicySpecifier parentCompositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                null, topLevelCompositePolicySpecifier
        );

        String apJson = objMapper.writeValueAsString(parentCompositePolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositeAPObjectEquality(parentCompositePolicySpecifier, deserializedObj);

    }
    @Test
    public void threeSingleTokenCompositeAccessPolicyAPDeserialization() throws
            IOException, InvalidArgumentsException {

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

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingle = new HashSet<>();
        accessPoliciesSetSingle.add(testPolicySpecifierFirst);
        accessPoliciesSetSingle.add(testPolicySpecifierSecond);
        accessPoliciesSetSingle.add(testPolicySpecifierThird);


        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, null
        );

        String apJson = objMapper.writeValueAsString(compositePolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositeAPObjectEquality(compositePolicySpecifier, deserializedObj);


    }

    @Test
    public void fourSingleTokenCompositeAccessPolicyAPDeserialization() throws
            IOException, InvalidArgumentsException {

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

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingle = new HashSet<>();
        accessPoliciesSetSingle.add(testPolicySpecifierFirst);
        accessPoliciesSetSingle.add(testPolicySpecifierSecond);
        accessPoliciesSetSingle.add(testPolicySpecifierThird);
        accessPoliciesSetSingle.add(testPolicySpecifierFourth);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, null
        );

        String apJson = objMapper.writeValueAsString(compositePolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositeAPObjectEquality(compositePolicySpecifier, deserializedObj);


    }

    @Test
    public void threeSingleTokenCompositeOneSingleAccessPolicyAPDeserialization() throws
            IOException, InvalidArgumentsException {

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

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingle = new HashSet<>();
        accessPoliciesSetSingle.add(testPolicySpecifierFirst);
        accessPoliciesSetSingle.add(testPolicySpecifierSecond);
        accessPoliciesSetSingle.add(testPolicySpecifierThird);

        CompositeAccessPolicySpecifier compositePolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingle, null
        );

        Set<SingleTokenAccessPolicySpecifier> accessPoliciesSetSingleSecond = new HashSet<>();
        accessPoliciesSetSingleSecond.add(testPolicySpecifierFourth);

        Set<CompositeAccessPolicySpecifier> compositeAccessPolicySpecifiers = new HashSet<>();
        compositeAccessPolicySpecifiers.add(compositePolicySpecifier);

        CompositeAccessPolicySpecifier parentPolicySpecifier = new CompositeAccessPolicySpecifier(
                CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND,
                accessPoliciesSetSingleSecond, compositeAccessPolicySpecifiers
        );

        String apJson = objMapper.writeValueAsString(parentPolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositeAPObjectEquality(parentPolicySpecifier, deserializedObj);


    }

    @Test
    public void attributeOrientedAPDeserialization() throws
            IOException, InvalidArgumentsException {

        AccessPolicyType refAPType = AccessPolicyType.PAOAP;

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

        AttributeOrientedAccessPolicySpecifier testPolicySpecifier = new AttributeOrientedAccessPolicySpecifier(
                compositeAR2
        );

        String apJson = objMapper.writeValueAsString(testPolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertAttributeOrientedAPObjectEquality(testPolicySpecifier, deserializedObj);
    }

    @Test
    public void platformAttributeOrientedAPDeserialization() throws
            IOException, InvalidArgumentsException {

        AccessPolicyType refAPType = AccessPolicyType.PAOAP;

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

        PlatformAttributeOrientedAccessPolicySpecifier testPolicySpecifier = new PlatformAttributeOrientedAccessPolicySpecifier(
                platformId,
                new AttributeOrientedAccessPolicySpecifier(compositeAR2).getAccessRules()
        );

        String apJson = objMapper.writeValueAsString(testPolicySpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertPlatformAttributeOrientedAPObjectEquality(testPolicySpecifier, deserializedObj);
    }

    @Test
    public void compositePlatformAttributeOrientedAPDeserialization() throws
            IOException, InvalidArgumentsException {

        AccessPolicyType refAPType = AccessPolicyType.CPAOAP;

        BooleanAccessRule booleanAccessRule = new BooleanAccessRule(SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + fromEUAttr, BooleanAccessRule.BooleanRelationalOperator.IS_TRUE);

        NumericAccessRule numAccessRule1 = new NumericAccessRule(18, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.GREATER_THAN);
        NumericAccessRule numAccessRule2 = new NumericAccessRule(20, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + ageAttr, NumericAccessRule.NumericRelationalOperator.LESS_THAN);
        StringAccessRule stringAccessRule = new StringAccessRule(nameAttrOKValue, SecurityConstants.SYMBIOTE_ATTRIBUTES_PREFIX + nameAttr, StringAccessRule.StringRelationalOperator.EQUALS);

        Set<IAccessRule> arSet1 = new HashSet<>();
        arSet1.add(stringAccessRule);
        arSet1.add(booleanAccessRule);

        CompositeAccessRule compositeAR1 = new CompositeAccessRule(arSet1, CompositeAccessRule.CompositeAccessRulesOperator.OR);

        PlatformAttributeOrientedAccessPolicySpecifier testPolicySpecifier1 = new PlatformAttributeOrientedAccessPolicySpecifier(
                platformId,
                new AttributeOrientedAccessPolicySpecifier(compositeAR1).getAccessRules()
        );

        PlatformAttributeOrientedAccessPolicySpecifier testPolicySpecifier2 = new PlatformAttributeOrientedAccessPolicySpecifier(
                platformId2,
                new AttributeOrientedAccessPolicySpecifier(numAccessRule2).getAccessRules()
        );

        PlatformAttributeOrientedAccessPolicySpecifier testPolicySpecifier3 = new PlatformAttributeOrientedAccessPolicySpecifier(
                platformId3,
                new AttributeOrientedAccessPolicySpecifier(numAccessRule1).getAccessRules()
        );

        Set<PlatformAttributeOrientedAccessPolicySpecifier> singlePAOAPs = new HashSet<>();
        singlePAOAPs.add(testPolicySpecifier1);

        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> compositePAOAPs = new HashSet<>();
        Set<PlatformAttributeOrientedAccessPolicySpecifier> singlePAOAPs2 = new HashSet<>();
        singlePAOAPs2.add(testPolicySpecifier2);
        singlePAOAPs2.add(testPolicySpecifier3);

        CompositePlatformAttributeOrientedAccessPolicySpecifier compPAOAP = new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.OR, singlePAOAPs2, null);

        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> compositePAOAPsFinal = new HashSet<>();
        compositePAOAPsFinal.add(compPAOAP);

        CompositePlatformAttributeOrientedAccessPolicySpecifier cpaoapSpecifier = new CompositePlatformAttributeOrientedAccessPolicySpecifier(CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.AND, singlePAOAPs, compositePAOAPsFinal);

        String apJson = objMapper.writeValueAsString(cpaoapSpecifier);

        JsonParser parser = jsonFactory.createParser(apJson);

        IAccessPolicySpecifier deserializedObj = jsonDeserializer.deserialize(parser, null);

        assertCompositePlatformAttributeOrientedAPObjectEquality(cpaoapSpecifier, deserializedObj);
    }

    private void assertSingleTokenAPObjectEquality(SingleTokenAccessPolicySpecifier refAPObject, IAccessPolicySpecifier deserializedAPObject) throws InvalidArgumentsException {

        if (deserializedAPObject instanceof SingleTokenAccessPolicySpecifier) {

            SingleTokenAccessPolicySpecifier stAPObject = (SingleTokenAccessPolicySpecifier) deserializedAPObject;
            //Verify that AP is of the same type
            Assert.assertEquals(stAPObject.getPolicyType(), refAPObject.getPolicyType());
            //Verify that required claims are the same
            if (refAPObject.getRequiredClaims() != null) {
                Assert.assertNotNull(stAPObject.getRequiredClaims());

                Assert.assertEquals(stAPObject.getRequiredClaims().size(), refAPObject.getRequiredClaims().size());
                for (Map.Entry<String, String> entry : refAPObject.getRequiredClaims().entrySet()) {
                    Assert.assertEquals(entry.getValue(), stAPObject.getRequiredClaims().get(entry.getKey()));
                }
            }

        } else {
            throw new InvalidArgumentsException("Deserialized object is not instance of SingleTokenAccessPolicySpecifier");
        }
    }

    private void assertCompositeAPObjectEquality(CompositeAccessPolicySpecifier refAPObject, IAccessPolicySpecifier deserializedAPObject) throws InvalidArgumentsException {

        if (deserializedAPObject instanceof CompositeAccessPolicySpecifier) {

            CompositeAccessPolicySpecifier cAPObject = (CompositeAccessPolicySpecifier) deserializedAPObject;
            //Verify that AP is of the same type
            Assert.assertEquals(cAPObject.getPolicyType(), refAPObject.getPolicyType());
            //Verify that CAP has the same logical operator
            Assert.assertEquals(cAPObject.getRelationOperator(), refAPObject.getRelationOperator());

            //verify that incorporated SingleTokenAPs are equal
            if (refAPObject.getSingleTokenAccessPolicySpecifiers() != null) {
                Assert.assertNotNull(cAPObject.getSingleTokenAccessPolicySpecifiers());

                Assert.assertEquals(cAPObject.getSingleTokenAccessPolicySpecifiers().size(), refAPObject.getSingleTokenAccessPolicySpecifiers().size());

                Iterator iter = cAPObject.getSingleTokenAccessPolicySpecifiers().iterator();

                for (SingleTokenAccessPolicySpecifier stapSpecifier : cAPObject.getSingleTokenAccessPolicySpecifiers()) {
                    SingleTokenAccessPolicySpecifier deserializedStAPObj = (SingleTokenAccessPolicySpecifier) iter.next();
                    assertSingleTokenAPObjectEquality(stapSpecifier, deserializedStAPObj);
                }
            }

            //verify that incorporated CompositeAPs are equal
            if (refAPObject.getCompositeAccessPolicySpecifiers() != null) {
                Assert.assertNotNull(cAPObject.getCompositeAccessPolicySpecifiers());

                Assert.assertEquals(cAPObject.getCompositeAccessPolicySpecifiers().size(), refAPObject.getCompositeAccessPolicySpecifiers().size());

                Iterator iter = cAPObject.getCompositeAccessPolicySpecifiers().iterator();

                for (CompositeAccessPolicySpecifier capSpecifier : cAPObject.getCompositeAccessPolicySpecifiers()) {
                    CompositeAccessPolicySpecifier deserializedStAPObj = (CompositeAccessPolicySpecifier) iter.next();
                    assertCompositeAPObjectEquality(capSpecifier, deserializedStAPObj);
                }
            }
        } else {
            throw new InvalidArgumentsException("Deserialized object is not instance of SingleTokenAccessPolicySpecifier");
        }
    }

    private void assertAttributeOrientedAPObjectEquality(AttributeOrientedAccessPolicySpecifier refAOAPObject, IAccessPolicySpecifier deserializedAPObject) throws InvalidArgumentsException {

        if (deserializedAPObject instanceof AttributeOrientedAccessPolicySpecifier) {

            AttributeOrientedAccessPolicySpecifier attrOrientedAPObject = (AttributeOrientedAccessPolicySpecifier) deserializedAPObject;
            //Verify that AOAP is of the same type
            Assert.assertEquals(attrOrientedAPObject.getPolicyType(), refAOAPObject.getPolicyType());
            //Verify that access rules are the same
            if (refAOAPObject.getAccessRules() != null) {
                Assert.assertNotNull(attrOrientedAPObject.getAccessRules());
                Assert.assertEquals(attrOrientedAPObject.getAccessRules().getAccessRuleType(), refAOAPObject.getAccessRules().getAccessRuleType());

            }

        } else {
            throw new InvalidArgumentsException("Deserialized object is not instance of AttributeOrientedAccessPolicySpecifier");
        }
    }

    private void assertPlatformAttributeOrientedAPObjectEquality(PlatformAttributeOrientedAccessPolicySpecifier refAOAPObject, IAccessPolicySpecifier deserializedAPObject) throws InvalidArgumentsException {

        if (deserializedAPObject instanceof PlatformAttributeOrientedAccessPolicySpecifier) {

            PlatformAttributeOrientedAccessPolicySpecifier platformAttrOrientedAPObject = (PlatformAttributeOrientedAccessPolicySpecifier) deserializedAPObject;
            //Verify that PAOAP is of the same type
            Assert.assertEquals(platformAttrOrientedAPObject.getPolicyType(), refAOAPObject.getPolicyType());
            Assert.assertEquals(platformAttrOrientedAPObject.getPlatformIdentifier(), refAOAPObject.getPlatformIdentifier());
            //Verify that access rules are the same
            if (refAOAPObject.getAccessRules() != null) {
                Assert.assertNotNull(platformAttrOrientedAPObject.getAccessRules());
                Assert.assertEquals(platformAttrOrientedAPObject.getAccessRules().getAccessRuleType(), refAOAPObject.getAccessRules().getAccessRuleType());

            }

        } else {
            throw new InvalidArgumentsException("Deserialized object is not instance of PlatformAttributeOrientedAccessPolicySpecifier");
        }
    }

    private void assertCompositePlatformAttributeOrientedAPObjectEquality(CompositePlatformAttributeOrientedAccessPolicySpecifier refAPObject, IAccessPolicySpecifier deserializedAPObject) throws InvalidArgumentsException {

        if (deserializedAPObject instanceof CompositePlatformAttributeOrientedAccessPolicySpecifier) {

            CompositePlatformAttributeOrientedAccessPolicySpecifier cPAOAPObj = (CompositePlatformAttributeOrientedAccessPolicySpecifier) deserializedAPObject;
            //Verify that CPAOAP is of the same type
            Assert.assertEquals(cPAOAPObj.getPolicyType(), refAPObject.getPolicyType());
            //Verify that CPAOAP has the same logical operator
            Assert.assertEquals(cPAOAPObj.getPoliciesRelationOperator(), refAPObject.getPoliciesRelationOperator());

            //verify that incorporated SingleTokenAPs PAOAPs are equal
            if (refAPObject.getSinglePlatformAttrOrientedAccessPolicies() != null) {
                Assert.assertNotNull(cPAOAPObj.getSinglePlatformAttrOrientedAccessPolicies());

                Assert.assertEquals(cPAOAPObj.getSinglePlatformAttrOrientedAccessPolicies().size(), refAPObject.getSinglePlatformAttrOrientedAccessPolicies().size());

                Iterator iter = cPAOAPObj.getSinglePlatformAttrOrientedAccessPolicies().iterator();

                for (PlatformAttributeOrientedAccessPolicySpecifier spaoapSpecifier : cPAOAPObj.getSinglePlatformAttrOrientedAccessPolicies()) {
                    PlatformAttributeOrientedAccessPolicySpecifier deserializedStAPObj = (PlatformAttributeOrientedAccessPolicySpecifier) iter.next();
                    assertPlatformAttributeOrientedAPObjectEquality(spaoapSpecifier, deserializedStAPObj);
                }
            }

            //verify that incorporated Composite PAOAPs are equal
            if (refAPObject.getCompositePlatformAttrOrientedAccessPolicies() != null) {
                Assert.assertNotNull(cPAOAPObj.getCompositePlatformAttrOrientedAccessPolicies());

                Assert.assertEquals(cPAOAPObj.getCompositePlatformAttrOrientedAccessPolicies().size(), refAPObject.getCompositePlatformAttrOrientedAccessPolicies().size());

                Iterator iter = cPAOAPObj.getCompositePlatformAttrOrientedAccessPolicies().iterator();

                for (CompositePlatformAttributeOrientedAccessPolicySpecifier cpaoapSpecifier : cPAOAPObj.getCompositePlatformAttrOrientedAccessPolicies()) {
                    CompositePlatformAttributeOrientedAccessPolicySpecifier deserializedStAPObj = (CompositePlatformAttributeOrientedAccessPolicySpecifier) iter.next();
                    assertCompositePlatformAttributeOrientedAPObjectEquality(cpaoapSpecifier, deserializedStAPObj);
                }
            }
        } else {
            throw new InvalidArgumentsException("Deserialized object is not instance of CompositePlatformAttributeOrientedAccessPolicySpecifier");
        }
    }
}