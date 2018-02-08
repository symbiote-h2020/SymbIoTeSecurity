package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.BooleanAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.CompositeAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.NumericAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.StringAccessRule;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.AccessRuleType;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.springframework.data.annotation.PersistenceConstructor;

import java.io.IOException;

/**
 * Specifies the sample access policy. It is used by {@link eu.h2020.symbiote.security.accesspolicies.common.AttributeOrientedAccessPolicyFactory AttributeOrientedAccessPolicyFactory}
 * to create the sample attribute-oriented access policy POJO.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class AttributeOrientedAccessPolicySpecifier implements IAccessPolicySpecifier {

    private final IAccessRule accessRules;
    private final AccessPolicyType accessPolicyType;

    @JsonCreator
    @PersistenceConstructor
    public AttributeOrientedAccessPolicySpecifier(@JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_ACCESS_RULES) IAccessRule accessRules) {
        this.accessRules = accessRules;
        this.accessPolicyType = AccessPolicyType.AOAP;

    }

    public AttributeOrientedAccessPolicySpecifier(String accessRulesJSON) throws IOException {
        ObjectMapper objMapper = new ObjectMapper();
        ObjectNode objNode = objMapper.readValue(accessRulesJSON, ObjectNode.class);
        String accessRuleType = objNode.get("accessRuleType").asText();
        switch (AccessRuleType.valueOf(accessRuleType)) {
            case COMPOSITE:
                this.accessRules = new CompositeAccessRule(accessRulesJSON);
                break;
            case STRING:
                this.accessRules = new StringAccessRule(accessRulesJSON);
                break;
            case NUMERIC:
                this.accessRules = new NumericAccessRule(accessRulesJSON);
                break;
            case BOOLEAN:
                this.accessRules = new BooleanAccessRule(accessRulesJSON);
                break;
            default:
                this.accessRules = null;
                break;
        }

        this.accessPolicyType = AccessPolicyType.AOAP;

    }

    public IAccessRule getAccessRules() {
        return accessRules;
    }

    @Override
    public AccessPolicyType getPolicyType() {
        return this.accessPolicyType;
    }

}
