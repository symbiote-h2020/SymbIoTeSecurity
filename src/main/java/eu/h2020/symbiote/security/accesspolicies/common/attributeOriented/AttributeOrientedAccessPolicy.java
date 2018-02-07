package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.Token;

import java.util.Set;

/**
 * SymbIoTe Access Policies based on attribute-oriented access rules that needs to be satisfied by one or multiple Token:
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class AttributeOrientedAccessPolicy implements IAccessPolicy {

    private final IAccessRule accessRules;

    /**
     * Creates a new access policy object
     */
    public AttributeOrientedAccessPolicy(IAccessRule accessRules) {
        this.accessRules = accessRules;
    }

    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {

        return accessRules.isMet(authorizationTokens);
    }

}
