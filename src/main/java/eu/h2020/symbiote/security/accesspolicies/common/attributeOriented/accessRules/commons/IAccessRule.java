package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.h2020.symbiote.security.commons.Token;

import java.util.Set;

/**
 * Interface that all access rules in SymbIoTe need to implement
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public interface IAccessRule {

    /**
     * @param authorizationTokens - set of tokens that should be evaluated agains access rule
     * @return - Set of tokens that were compliant with access rule
     */
    Set<Token> isMet(Set<Token> authorizationTokens);

    /**
     * @return Access rules type of the implementing class
     */
    AccessRuleType getAccessRuleType();

    /**
     * @return JSON printout of the access rule fields
     */
    String toJSONString() throws JsonProcessingException;

}
