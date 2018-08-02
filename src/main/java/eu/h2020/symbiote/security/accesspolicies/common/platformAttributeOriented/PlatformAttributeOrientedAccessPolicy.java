package eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.Token;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access Policies based on platform attribute-oriented access rules that needs to be satisfied by one or multiple Token issued by specific platform:
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class PlatformAttributeOrientedAccessPolicy implements IAccessPolicy {

    private final String platformIdentifier;
    private final IAccessRule accessRules;

    /**
     * Creates a new access policy object
     */
    public PlatformAttributeOrientedAccessPolicy(String platformIdentifier, IAccessRule accessRules) {
        this.platformIdentifier = platformIdentifier;
        this.accessRules = accessRules;
    }

    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {

        //extract only tokens for particular platformIdentifier
        Set<Token> platformTokens = new HashSet<>();
        for (Token token : authorizationTokens) {
            //verify if token is issued by required platform
            if (token.getClaims().getIssuer().equals(platformIdentifier)) {
                platformTokens.add(token);
            }
        }

        return accessRules.isMet(platformTokens);
    }

}
