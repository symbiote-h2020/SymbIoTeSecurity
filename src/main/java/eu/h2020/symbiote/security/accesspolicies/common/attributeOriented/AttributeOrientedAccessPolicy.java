package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policies based on attribute-oriented access rules that needs to be satisfied by one or multiple Token:
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class AttributeOrientedAccessPolicy implements IAccessPolicy {

    /**
     * Creates a new access policy object
     */
    public AttributeOrientedAccessPolicy() throws
            InvalidArgumentsException {

    }

    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {

        Set<Token> returnTokensSet = new HashSet<>();
        returnTokensSet.addAll(authorizationTokens);
        return returnTokensSet;
    }

}
