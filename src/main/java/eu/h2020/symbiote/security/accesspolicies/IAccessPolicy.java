package eu.h2020.symbiote.security.accesspolicies;

import eu.h2020.symbiote.security.commons.Token;

import java.util.List;

/**
 * Interface that all access policies in SymbIoTe policies need to implement
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface IAccessPolicy {

    /**
     * @param authorizationTokens that might satisfy the policy
     * @return true if the given tokens satisfy the policy
     */
    boolean isSatisfiedWith(List<Token> authorizationTokens);
}
