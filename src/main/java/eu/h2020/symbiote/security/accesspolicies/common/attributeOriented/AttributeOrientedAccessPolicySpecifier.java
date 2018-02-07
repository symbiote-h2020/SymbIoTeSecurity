package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import org.springframework.data.annotation.PersistenceConstructor;

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

    public IAccessRule getAccessRules() {
        return accessRules;
    }

    @Override
    public AccessPolicyType getPolicyType() {
        return this.accessPolicyType;
    }

}
