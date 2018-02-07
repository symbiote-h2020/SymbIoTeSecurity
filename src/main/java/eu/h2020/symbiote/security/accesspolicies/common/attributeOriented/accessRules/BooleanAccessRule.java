package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules;

import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.AccessRuleType;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access rules for Boolean data type values
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class BooleanAccessRule implements IAccessRule {

    private String attributeName;
    private BooleanRelationalOperator operator;
    private final AccessRuleType ruleType = AccessRuleType.BOOLEAN;

    /**
     * @param attributeName - Name of the attribute whose value should be compared
     * @param operator      - Comparison operator
     */
    public BooleanAccessRule(String attributeName, BooleanRelationalOperator operator) {
        this.attributeName = attributeName;
        this.operator = operator;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public void setOperator(BooleanRelationalOperator operator) {
        this.operator = operator;
    }

    @Override
    public Set<Token> isMet(Set<Token> authorizationTokens) {
        Set<Token> validTokens = new HashSet<>();
        for (Token token : authorizationTokens) {
            //Extract attribute value from token
            String controlledValueString = token.getClaims().get(attributeName, String.class);
            //Evaluate attribute value against operator
            if (controlledValueString != null) {
                switch (this.operator) {
                    case IS_TRUE:
                        if (controlledValueString.toLowerCase().equals(SecurityConstants.BOOLEAN_STRING_VALUE_TRUE)) {
                            validTokens.add(token);
                        }
                        break;
                    case IS_FALSE:
                        if (controlledValueString.toLowerCase().equals(SecurityConstants.BOOLEAN_STRING_VALUE_FALSE)) {
                            validTokens.add(token);
                        }
                        break;
                    default:
                }
            }
        }
        return validTokens;

    }

    @Override
    public AccessRuleType getAccessRuleType() {
        return this.ruleType;
    }

    /**
     * Enumeration for specifying the expression type for the Boolean access rule.
     *
     * @author Nemanja Ignjatov (UNIVIE)
     */
    public enum BooleanRelationalOperator {
        /**
         * is provided falue TRUE
         */
        IS_TRUE,
        /**
         * is provided falue FALSE
         */
        IS_FALSE,

    }

}
