package eu.h2020.symbiote.security.accesspolicies;

import eu.h2020.symbiote.security.commons.Token;

import java.util.Set;

/**
 * Interface that all access policies in SymbIoTe policies need to implement
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface IAccessPolicy {

    /**
     * @param deploymentId id of the Security libraries deployment
     * @param authorizationTokens that might satisfy the policy
     * @return First token that satisfied access policy
     */
    Token isSatisfiedWith(String deploymentId, Set<Token> authorizationTokens);
}
