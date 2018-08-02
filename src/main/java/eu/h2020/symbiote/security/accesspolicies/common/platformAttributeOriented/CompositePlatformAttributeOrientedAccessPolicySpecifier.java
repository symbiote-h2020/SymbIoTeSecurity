package eu.h2020.symbiote.security.accesspolicies.common.platformAttributeOriented;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.composite.CompositeAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import org.springframework.data.annotation.PersistenceConstructor;

import java.util.Set;

/**
 * Specifies the sample composite platform attribute oriented access policy. It is used by {@link eu.h2020.symbiote.security.accesspolicies.common.AttributeOrientedAccessPolicyFactory AttributeOrientedAccessPolicyFactory}
 * to create the sample composite platform attribute-oriented access policy POJO.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class CompositePlatformAttributeOrientedAccessPolicySpecifier implements IAccessPolicySpecifier {

    private final CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator policiesRelationOperator;
    private final Set<PlatformAttributeOrientedAccessPolicySpecifier> singlePlatformAttrOrientedAccessPolicies;
    private final Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> compositePlatformAttrOrientedAccessPolicies;
    private final AccessPolicyType accessPolicyType;

    /**
     * Constructor of CompositePlatformAttributeOrientedAccessPolicySpecifier
     *
     * @param policiesRelationOperator                    logical operator between access policies
     * @param singlePlatformAttrOrientedAccessPolicies    Set of single platform attribute oriented access policies that should be validated for gaining/restricting access
     * @param compositePlatformAttrOrientedAccessPolicies Set of single composite attribute oriented access policies that should be validated for gaining/restricting access
     */
    @JsonCreator
    @PersistenceConstructor
    public CompositePlatformAttributeOrientedAccessPolicySpecifier(
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_OPERATOR) CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator policiesRelationOperator,
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_SINGLE_TOKEN_AP) Set<PlatformAttributeOrientedAccessPolicySpecifier> singlePlatformAttrOrientedAccessPolicies,
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_COMPOSITE_AP) Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> compositePlatformAttrOrientedAccessPolicies)
            throws InvalidArgumentsException {

        if (((singlePlatformAttrOrientedAccessPolicies == null) || (singlePlatformAttrOrientedAccessPolicies.isEmpty())) &&
                ((compositePlatformAttrOrientedAccessPolicies == null) || (compositePlatformAttrOrientedAccessPolicies.isEmpty()))) {
            throw new InvalidArgumentsException("At least one access policy has to be defined!");
        }

        this.singlePlatformAttrOrientedAccessPolicies = singlePlatformAttrOrientedAccessPolicies;
        this.compositePlatformAttrOrientedAccessPolicies = compositePlatformAttrOrientedAccessPolicies;
        this.policiesRelationOperator = policiesRelationOperator;
        this.accessPolicyType = AccessPolicyType.CPAOAP;

    }

    public CompositeAccessPolicySpecifier.CompositeAccessPolicyRelationOperator getPoliciesRelationOperator() {
        return policiesRelationOperator;
    }

    public Set<PlatformAttributeOrientedAccessPolicySpecifier> getSinglePlatformAttrOrientedAccessPolicies() {
        return singlePlatformAttrOrientedAccessPolicies;
    }

    public Set<CompositePlatformAttributeOrientedAccessPolicySpecifier> getCompositePlatformAttrOrientedAccessPolicies() {
        return compositePlatformAttrOrientedAccessPolicies;
    }

    @Override
    public AccessPolicyType getPolicyType() {
        return this.accessPolicyType;
    }

}
