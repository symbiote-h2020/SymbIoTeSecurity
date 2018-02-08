package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.AccessRuleType;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;

import java.io.IOException;
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
    private final AccessRuleType accessRuleType = AccessRuleType.BOOLEAN;

    /**
     * @param attributeName - Name of the attribute whose value should be compared
     * @param operator      - Comparison operator
     */
    public BooleanAccessRule(String attributeName, BooleanRelationalOperator operator) {
        this.attributeName = attributeName;
        this.operator = operator;
    }

    public BooleanAccessRule() {
    }

    /**
     * @param accessRuleJson - String containing JSON formatted Boolean access rule
     * @throws IOException
     */
    public BooleanAccessRule(String accessRuleJson) throws IOException {
        ObjectMapper objMapper = new ObjectMapper();
        BooleanAccessRule boolArObj = objMapper.readValue(accessRuleJson, BooleanAccessRule.class);
        this.attributeName = boolArObj.attributeName;
        this.operator = boolArObj.operator;
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
        return this.accessRuleType;
    }

    @Override
    public String toJSONString() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public String getAttributeName() {
        return attributeName;
    }

    public BooleanRelationalOperator getOperator() {
        return operator;
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
