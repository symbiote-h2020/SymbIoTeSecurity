/*
 * ---------------------------------------------------------------------
 * Kiwi Remote Instrumentation Platform
 * http://kiwi.man.poznan.pl
 * Copyright (C) 2010-2013
 * ---------------------------------------------------------------------
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contributors:
 *
 */
package eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules;

import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.AccessRuleType;
import eu.h2020.symbiote.security.accesspolicies.common.attributeOriented.accessRules.commons.IAccessRule;
import eu.h2020.symbiote.security.commons.Token;

import java.util.Set;

/**
 * Allows building rules which verify a value against relational operators
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class CompositeAccessRule implements IAccessRule {

    private final Set<IAccessRule> accessRules;
    private final CompositeAccessRulesOperator operator;
    private final AccessRuleType ruleType = AccessRuleType.COMPOSITE;

    public CompositeAccessRule(Set<IAccessRule> accessRules, CompositeAccessRulesOperator operator) {
        this.accessRules = accessRules;
        this.operator = operator;
    }

    @Override
    public Set<Token> isMet(Set<Token> authorizationTokens) {

        return null;
    }

    @Override
    public AccessRuleType getAccessRuleType() {
        return this.ruleType;
    }

    /**
     * Enumeration for specifying the relation operator between access rules
     *
     * @author Nemanja Ignjatov (UNIVIE)
     */
    public enum CompositeAccessRulesOperator {
        // AND logical operator for describing relations between access rules
        AND,
        // OR logical operator for describing relations between access rules
        OR,
        // NAND logical operator for describing relations between access rules
        NAND,
        // NOR logical operator for describing relations between access rules
        NOR
    }
}
