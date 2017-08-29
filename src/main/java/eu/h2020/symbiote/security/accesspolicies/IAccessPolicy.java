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
     * @param authorizationTokens that might satisfy the policy
     * @return Set of tokens that satisfied access policy, if the result set is empty then the policy is NOT satisfied!
     */
    Set<Token> isSatisfiedWith(Set<Token> authorizationTokens);
}
