package eu.h2020.symbiote.security.helpers.accesspolicies;


import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyJSONDeserializer;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
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

    private final String username = "testusername";
    private final String clientId = "testclientid";
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
    private final String ageAttrBadValue = "33";

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
}