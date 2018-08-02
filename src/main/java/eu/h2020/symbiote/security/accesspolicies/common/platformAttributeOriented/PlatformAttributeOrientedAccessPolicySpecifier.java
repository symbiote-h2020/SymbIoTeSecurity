package eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented;

import com.fasterxml.jackson.annotation.JsonCreator;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.AttributeOrientedAccessPolicySpecifier;
import org.springframework.data.annotation.PersistenceConstructor;

import java.io.IOException;

/**
 * Specifies the sample platform attribute oriented access policy. It is used by {@link eu.h2020.symbiote.security.accesspolicies.common.AttributeOrientedAccessPolicyFactory AttributeOrientedAccessPolicyFactory}
 * to create the sample platform attribute-oriented access policy POJO.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class PlatformAttributeOrientedAccessPolicySpecifier implements IAccessPolicySpecifier {

    private final AttributeOrientedAccessPolicySpecifier attrOrientedAccessPolicySpecifier;
    private final String platformIdentifier;
    private final AccessPolicyType accessPolicyType;

    @JsonCreator
    @PersistenceConstructor
    public PlatformAttributeOrientedAccessPolicySpecifier(String platformIdentifier, AttributeOrientedAccessPolicySpecifier attrOrientedAccessPolicySpecifier) {
        this.attrOrientedAccessPolicySpecifier = attrOrientedAccessPolicySpecifier;
        this.platformIdentifier = platformIdentifier;
        this.accessPolicyType = AccessPolicyType.PAOAP;

    }

    public PlatformAttributeOrientedAccessPolicySpecifier(String platformIdentifier, String accessRulesJSON) throws IOException {
        this.platformIdentifier = platformIdentifier;
        this.attrOrientedAccessPolicySpecifier = new AttributeOrientedAccessPolicySpecifier(accessRulesJSON);
        this.accessPolicyType = AccessPolicyType.PAOAP;

    }

    public AttributeOrientedAccessPolicySpecifier getAttrOrientedAccessPolicySpecifier() {
        return attrOrientedAccessPolicySpecifier;
    }

    public String getPlatformIdentifier() {
        return platformIdentifier;
    }

    @Override
    public AccessPolicyType getPolicyType() {
        return this.accessPolicyType;
    }

}
