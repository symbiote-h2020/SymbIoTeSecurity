package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules;

import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.AccessRuleType;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.Token;

import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access rules for String (Text) data type values
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class StringAccessRule implements IAccessRule {

    private String attributeName;
    private String expectedValue;
    private StringRelationalOperator operator;
    private final AccessRuleType ruleType = AccessRuleType.STRING;

    /**
     * @param expectedValue - String value that is to be compared
     * @param attributeName - Name of the attribute whose value should be compared
     * @param operator      - Comparison operator
     */
    public StringAccessRule(String expectedValue, String attributeName, StringRelationalOperator operator) {
        this.expectedValue = expectedValue;
        this.attributeName = attributeName;
        this.operator = operator;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public void setOperator(StringRelationalOperator operator) {
        this.operator = operator;
    }

    @Override
    public Set<Token> isMet(Set<Token> authorizationTokens) {
        Set<Token> validTokens = new HashSet<>();
        for (Token token : authorizationTokens) {
            //Extract value from attribute
            String controlledVal = token.getClaims().get(attributeName, String.class);
            //Validate if value is present and evaluate the expression
            if ((controlledVal != null) &&
                    evaluateStringExpression(this.expectedValue, controlledVal, this.operator)) {
                validTokens.add(token);
            }
        }
        return validTokens;

    }

    @Override
    public AccessRuleType getAccessRuleType() {
        return this.ruleType;
    }

    private boolean evaluateStringExpression(String expectedVal, String controlledVal, StringRelationalOperator operator) {
        switch (operator) {
            case EQUALS:
                return (expectedVal.equals(controlledVal)) ? true : false;
            case EQUALS_IGNORE_CASE:
                return (expectedVal.equalsIgnoreCase(controlledVal)) ? true : false;
            case CONTAINS:
                return (expectedVal.contains(controlledVal)) ? true : false;
            case CONTAINS_IGNORE_CASE:
                return (expectedVal.toLowerCase().contains(controlledVal.toLowerCase())) ? true : false;
            case NOT_CONTAINS:
                return (!expectedVal.contains(controlledVal)) ? true : false;
            case NOT_CONTAINS_IGNORE_CASE:
                return (!expectedVal.toLowerCase().equals(controlledVal.toLowerCase())) ? true : false;
            case STARTS_WITH:
                return (expectedVal.startsWith(controlledVal)) ? true : false;
            case STARTS_WITH_IGNORE_CASE:
                return (expectedVal.toLowerCase().startsWith(controlledVal.toLowerCase())) ? true : false;
            case ENDS_WITH:
                return (expectedVal.endsWith(controlledVal)) ? true : false;
            case ENDS_WITH_IGNORE_CASE:
                return (expectedVal.toLowerCase().endsWith(controlledVal.toLowerCase())) ? true : false;
            case REGEXP:
                return false;//TODO implement
            default:
                return false;
        }
    }

    /**
     * Enumeration for specifying the expression type for the String-based access rule.
     *
     * @author Nemanja Ignjatov (UNIVIE)
     */
    public enum StringRelationalOperator {
        EQUALS,
        EQUALS_IGNORE_CASE,
        CONTAINS,
        CONTAINS_IGNORE_CASE,
        NOT_CONTAINS,
        NOT_CONTAINS_IGNORE_CASE,
        STARTS_WITH,
        STARTS_WITH_IGNORE_CASE,
        ENDS_WITH,
        ENDS_WITH_IGNORE_CASE,
        REGEXP
    }

}
