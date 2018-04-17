package eu.h2020.symbiote.security.accesspolicies.common;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
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
                case SLHTIBAP:
                case SLHTAP:
                case FRAPUSFOLHT:
                case FRAPUSHT:
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

    private SingleTokenAccessPolicySpecifier deserializeSingleTokenAccessPolicyJSON(ObjectMapper mapper, JsonNode node) throws InvalidArgumentsException {

        JsonNode policyType = node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_TYPE);
        AccessPolicyType apType = AccessPolicyType.valueOf(policyType.asText());

        Map<String, String> requiredClaims = mapper.convertValue(node.get(SecurityConstants.ACCESS_POLICY_JSON_FIELD_CLAIMS), Map.class);

        return new SingleTokenAccessPolicySpecifier(apType, requiredClaims);
    }

}
