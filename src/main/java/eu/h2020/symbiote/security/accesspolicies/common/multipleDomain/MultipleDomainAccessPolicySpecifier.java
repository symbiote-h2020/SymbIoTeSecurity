package eu.h2020.symbiote.security.accesspolicies.common.multipleDomain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import org.springframework.data.annotation.PersistenceConstructor;

import java.util.Set;

/**
 * Specifies the sample access policy. It is used by {@link eu.h2020.symbiote.security.accesspolicies.common.MultipleDomainAccessPolicyFactory MultipleDomainAccessPolicyFactory}
 * to create the sample access policy POJO.
 *
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class MultipleDomainAccessPolicySpecifier {

    private final MultipleDomainAccessPolicyRelationOperator policiesRelationOperator;
    private final Set<IAccessPolicy> accessPolicies;

    /**
     * Constructor of MultipleDomainAccessPolicySpecifier
     *
     * @param policiesRelationOperator logical operator between access policies
     * @param accessPolicies           Set of access policies that should be validated for gaining/restricting access
     */
    @JsonCreator
    @PersistenceConstructor
    public MultipleDomainAccessPolicySpecifier(
            @JsonProperty("policiesRelationOperator") MultipleDomainAccessPolicyRelationOperator policiesRelationOperator,
            @JsonProperty("accessPolicies") Set<IAccessPolicy> accessPolicies)
            throws InvalidArgumentsException {

        if ((accessPolicies == null) || (accessPolicies.isEmpty())) {
            throw new InvalidArgumentsException("At least one access policy has to be defined!");
        }

        this.accessPolicies = accessPolicies;
        this.policiesRelationOperator = policiesRelationOperator;

    }

    public MultipleDomainAccessPolicyRelationOperator getRelationOperator() {
        return policiesRelationOperator;
    }

    public Set<IAccessPolicy> getAccessPolicies() {
        return accessPolicies;
    }

    /**
     * Enumeration for specifying the relation operator between access policies
     *
     * @author Vasileios Glykantzis (ICOM)
     */
    public enum MultipleDomainAccessPolicyRelationOperator {

        AND,

        OR
    }
}
