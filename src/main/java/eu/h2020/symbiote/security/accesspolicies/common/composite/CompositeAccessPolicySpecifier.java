package eu.h2020.symbiote.security.accesspolicies.common.composite;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import org.springframework.data.annotation.PersistenceConstructor;

import java.util.Set;

/**
 * Specifies the sample access policy. It is used by {@link eu.h2020.symbiote.security.accesspolicies.common.CompositeAccessPolicyFactory CompositeAccessPolicyFactory}
 * to create the sample access policy POJO.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class CompositeAccessPolicySpecifier implements IAccessPolicySpecifier {

    private final CompositeAccessPolicyRelationOperator policiesRelationOperator;
    private final Set<SingleTokenAccessPolicySpecifier> singleTokenAccessPolicies;
    private final Set<CompositeAccessPolicySpecifier> compositeAccessPolicies;
    private final AccessPolicyType accessPolicyType;
    /**
     * Constructor of CompositeAccessPolicySpecifier
     *
     * @param policiesRelationOperator logical operator between access policies
     * @param singleTokenAccessPolicies           Set of access policies that should be validated for gaining/restricting access
     */
    @JsonCreator
    @PersistenceConstructor
    public CompositeAccessPolicySpecifier(
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_OPERATOR) CompositeAccessPolicyRelationOperator policiesRelationOperator,
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_SINGLE_TOKEN_AP) Set<SingleTokenAccessPolicySpecifier> singleTokenAccessPolicies,
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_COMPOSITE_AP) Set<CompositeAccessPolicySpecifier> compositeAccessPolicies)
            throws InvalidArgumentsException {

        if (((singleTokenAccessPolicies == null) || (singleTokenAccessPolicies.isEmpty())) &&
                ((compositeAccessPolicies == null) || (compositeAccessPolicies.isEmpty()))) {
            throw new InvalidArgumentsException("At least one access policy has to be defined!");
        }

        this.singleTokenAccessPolicies = singleTokenAccessPolicies;
        this.compositeAccessPolicies = compositeAccessPolicies;
        this.policiesRelationOperator = policiesRelationOperator;
        this.accessPolicyType = AccessPolicyType.CAP;

    }

    public CompositeAccessPolicyRelationOperator getRelationOperator() {
        return policiesRelationOperator;
    }

    public Set<SingleTokenAccessPolicySpecifier> getSingleTokenAccessPolicySpecifiers() {
        return singleTokenAccessPolicies;
    }

    public Set<CompositeAccessPolicySpecifier> getCompositeAccessPolicySpecifiers() {
        return compositeAccessPolicies;
    }

    @Override
    public AccessPolicyType getPolicyType() {
        return this.accessPolicyType;
    }

    /**
     * Enumeration for specifying the relation operator between access policies
     *
     * @author Nemanja Ignjatov (UNIVIE)
     */
    public enum CompositeAccessPolicyRelationOperator {
        // AND logical operator for describing relations between access policies
        AND,
        // OR logical operator for describing relations between access policies
        OR
    }
}
