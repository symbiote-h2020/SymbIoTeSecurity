package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented;

import com.fasterxml.jackson.annotation.JsonCreator;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import org.springframework.data.annotation.PersistenceConstructor;

/**
 * Specifies the sample access policy. It is used by {@link eu.h2020.symbiote.security.accesspolicies.common.AttributeOrientedAccessPolicyFactory AttributeOrientedAccessPolicyFactory}
 * to create the sample attribute-oriented access policy POJO.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class AttributeOrientedAccessPolicySpecifier implements IAccessPolicySpecifier {

    private final AccessPolicyType accessPolicyType;

    @JsonCreator
    @PersistenceConstructor
    public AttributeOrientedAccessPolicySpecifier()
            throws InvalidArgumentsException {

        this.accessPolicyType = AccessPolicyType.AOAP;

    }


    @Override
    public AccessPolicyType getPolicyType() {
        return this.accessPolicyType;
    }

}
