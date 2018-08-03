package eu.h2020.symbiote.security.accesspolicies.common;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.CompositePlatformAttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented.PlatformAttributeOrientedAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * JSON Deserializer for classes implementing {@link IAccessPolicySpecifier IAccessPolicySpecifier} interfaceSpecifies.
 * It is used to create the access policy specifier POJO.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class AccessPolicyJSONDeserializer extends JsonDeserializer<IAccessPolicySpecifier> {

    @Override
    public IAccessPolicySpecifier deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        try {
            ObjectCodec oc = jsonParser.getCodec();
            JsonNode node = oc.readTree(jsonParser);
            ObjectMapper mapper = new ObjectMapper();
            //Read type of access policy in JSON
            JsonNode policyType = node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_TYPE);
            //Invoke required deserializer from IAccessPolicy specifier
            AccessPolicyType apType = AccessPolicyType.valueOf(policyType.asText());
            switch (apType) {
                case CAP:
                    return deserializeCompositeAccessPolicyJSON(mapper, node);
                case AOAP:
                    return deserializeAttributeOrientedAccessPolicyJSON(mapper, node);
                case PAOAP:
                    return deserializePlatformAttributeOrientedAccessPolicyJSON(mapper, node);
                case CPAOAP:
                    return deserializeCompositePlatformAttributeOrientedAccessPolicyJSON(mapper, node);
                case SLHTIBAP:
                case SLHTAP:
                case SFTAP:
                case STAP:
                case CHTAP:
                case PUBLIC:
                    return deserializeSingleTokenAccessPolicyJSON(mapper, node);
                default:
                    throw new IOException(SecurityConstants.ERROR_DESC_UNSUPPORTED_ACCESS_POLICY_TYPE);

            }
        } catch (InvalidArgumentsException e) {
            throw new IOException(e);
        }
    }

    private CompositeAccessPolicySpecifier deserializeCompositeAccessPolicyJSON(ObjectMapper mapper, JsonNode node) throws InvalidArgumentsException {

        CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator operators = mapper.convertValue(node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_OPERATOR), CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.class);

        Set<SingleTokenAccessPolicySpecifier> staps = null;
        JsonNode stapsJsonNode = node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_SINGLE_TOKEN_AP);
        if ((stapsJsonNode != null) && !stapsJsonNode.isNull()) {
            staps = new HashSet<>();
            for (final JsonNode stapNode : stapsJsonNode) {
                staps.add(deserializeSingleTokenAccessPolicyJSON(mapper, stapNode));
            }
        }

        Set<CompositeAccessPolicySpecifier> caps = null;
        JsonNode capsJsonNode = node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_COMPOSITE_AP);
        if ((capsJsonNode != null) && !capsJsonNode.isNull()) {
            caps = new HashSet<>();
            for (final JsonNode capNode : capsJsonNode) {
                caps.add(deserializeCompositeAccessPolicyJSON(mapper, capNode));
            }
        }
        return new CompositeAccessPolicySpecifier(operators, staps, caps);
    }

    private AttributeOrientedAccessPolicySpecifier deserializeAttributeOrientedAccessPolicyJSON(ObjectMapper mapper, JsonNode node) throws InvalidArgumentsException, IOException {
        return new AttributeOrientedAccessPolicySpecifier(node.toString());
    }

    private PlatformAttributeOrientedAccessPolicySpecifier deserializePlatformAttributeOrientedAccessPolicyJSON(ObjectMapper mapper, JsonNode node) throws InvalidArgumentsException, IOException {
        JsonNode platformIdNode = node.get(SecurityConstants.ACCESS_POLICY_PLATFORM_ID);
        return new PlatformAttributeOrientedAccessPolicySpecifier(platformIdNode.asText(), new AttributeOrientedAccessPolicySpecifier(node.toString()).getAccessRules());
    }

    private CompositePlatformAttributeOrientedAccessPolicySpecifier deserializeCompositePlatformAttributeOrientedAccessPolicyJSON(ObjectMapper mapper, JsonNode node) throws InvalidArgumentsException, IOException {
        CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator operator = mapper.convertValue(node.get(SecurityConstants.ACCESS_POLICY_PLATFORM_RELATION_OPERATOR), CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator.class);

        Set<PlatformAttributeOrientedAccessPolicySpecifier> spaoaps = null;
        JsonNode spaoapsJsonNode = node.get(SecurityConstants.ACCESS_POLICY_SINGLE_PAOAPS);
        if ((spaoapsJsonNode != null) && !spaoapsJsonNode.isNull()) {
            spaoaps = new HashSet<PlatformAttributeOrientedAccessPolicySpecifier>();
            for (final JsonNode stapNode : spaoapsJsonNode) {
                spaoaps.add(deserializePlatformAttributeOrientedAccessPolicyJSON(mapper, stapNode));
            }
        }

        Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> cpaoaps = null;
        JsonNode capsJsonNode = node.get(SecurityConstants.ACCESS_POLICY_COMPOSITE_PAOAPS);
        if ((capsJsonNode != null) && !capsJsonNode.isNull()) {
            cpaoaps = new HashSet<CompositePlatformAttributeOrientedAccessPolicySpecifier>();
            for (final JsonNode capNode : capsJsonNode) {
                cpaoaps.add(deserializeCompositePlatformAttributeOrientedAccessPolicyJSON(mapper, capNode));
            }
        }
        return new CompositePlatformAttributeOrientedAccessPolicySpecifier(operator, spaoaps, cpaoaps);
    }

    private SingleTokenAccessPolicySpecifier deserializeSingleTokenAccessPolicyJSON(ObjectMapper mapper, JsonNode node) throws InvalidArgumentsException {

        JsonNode policyType = node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_TYPE);
        AccessPolicyType apType = AccessPolicyType.valueOf(policyType.asText());

        Map<String, String> requiredClaims = mapper.convertValue(node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_CLAIMS), Map.class);

        return new SingleTokenAccessPolicySpecifier(apType, requiredClaims);
    }

}
