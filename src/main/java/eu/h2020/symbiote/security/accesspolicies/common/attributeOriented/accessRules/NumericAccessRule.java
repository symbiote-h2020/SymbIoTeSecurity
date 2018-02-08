package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.AccessRuleType;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.Token;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.HashSet;
import java.util.Set;

/**
 * SymbIoTe Access rules for Numeric data type values
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class NumericAccessRule implements IAccessRule {

    private Number expectedValue;
    private String attributeName;
    private NumericRelationalOperator operator;
    private final AccessRuleType accessRuleType = AccessRuleType.NUMERIC;

    /**
     * @param expectedValue - Numeric value that is to be compared
     * @param attributeName - Name of the attribute whose value should be compared
     * @param operator      - Comparison operator
     */
    public NumericAccessRule(Number expectedValue, String attributeName, NumericRelationalOperator operator) {
        this.expectedValue = expectedValue;
        this.attributeName = attributeName;
        this.operator = operator;
    }

    public NumericAccessRule() {
    }

    /**
     * @param accessRuleJson - String containing JSON formatted Numeric access rule
     * @throws IOException -
     */
    public NumericAccessRule(String accessRuleJson) throws IOException {
        ObjectMapper objMapper = new ObjectMapper();
        NumericAccessRule numARObj = objMapper.readValue(accessRuleJson, NumericAccessRule.class);
        this.expectedValue = numARObj.expectedValue;
        this.attributeName = numARObj.attributeName;
        this.operator = numARObj.operator;
    }

    @Override
    public Set<Token> isMet(Set<Token> authorizationTokens) {
        Set<Token> validTokens = new HashSet<>();
        for (Token token : authorizationTokens) {
            try {
                //Extract value from attribute
                BigDecimal controlledVal = token.getClaims().get(attributeName, String.class) != null ? new BigDecimal(token.getClaims().get(attributeName, String.class)) : null;
                BigDecimal expectedVal = new BigDecimal(this.expectedValue.toString());
                //Validate if values are present and evaluate the expression
                if ((expectedVal != null) && (controlledVal != null) &&
                        evaluateNumericExpression(expectedVal, controlledVal, this.operator)) {
                    validTokens.add(token);
                }
            } catch (NumberFormatException e) {
            }
        }
        return validTokens;
    }

    @Override
    public AccessRuleType getAccessRuleType() {
        return this.accessRuleType;
    }

    @Override
    public String toJSONString() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public Number getExpectedValue() {
        return expectedValue;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public NumericRelationalOperator getOperator() {
        return operator;
    }

    private boolean evaluateNumericExpression(BigDecimal expectedVal, BigDecimal controlledVal, NumericRelationalOperator operator) {
        switch (operator) {
            case EQUALS:
                return (expectedVal.compareTo(controlledVal) == 0) ? true : false;
            case GREATER_OR_EQUAL_THAN:
                return (expectedVal.compareTo(controlledVal) < 0) ? true : false;
            case GREATER_THAN:
                return (expectedVal.compareTo(controlledVal) <= 0) ? true : false;
            case LESS_OR_EQUALS_THAN:
                return (expectedVal.compareTo(controlledVal) > 0) ? true : false;
            case LESS_THAN:
                return (expectedVal.compareTo(controlledVal) >= 0) ? true : false;
            case NOT_EQUALS:
                return (expectedVal.compareTo(controlledVal) != 0) ? true : false;
            default:
                return false;
        }
    }

    /**
     * Enumeration for specifying the expression type for the Numeric access rule.
     *
     * @author Nemanja Ignjatov (UNIVIE)
     */
    public enum NumericRelationalOperator {
        /**
         * equal
         */
        EQUALS,
        /**
         * not equal
         */
        NOT_EQUALS,
        /**
         * greater than
         */
        GREATER_THAN,
        /**
         * less than
         */
        LESS_THAN,
        /**
         * greater or equal
         */
        GREATER_OR_EQUAL_THAN,
        /**
         * less or equal
         */
        LESS_OR_EQUALS_THAN
    }
}
