package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import io.jsonwebtoken.Claims;

import java.util.HashMap;
import java.util.Map;

/**
 * Specifies the sample access policy. It is used by {@link SingleTokenAccessPolicyFactory SingleTokenAccessPolicyFactory}
 * to create the sample access policy POJO.
 *
 * @author Vasileios Glykantzis (ICOM)
 * @author Mikołaj Dobski (PSNC)
 */
public class SingleTokenAccessPolicySpecifier {
    private final SingleTokenAccessPolicyType policyType;
    private final Map<String, String> requiredClaims;

    /**
     * Constructor of SingleTokenAccessPolicySpecifier
     *
     * @param policyType     policyType of the sample access policy
     * @param requiredClaims map with all the claims that need to be contained in a single token to satisfy the
     *                       sample access policy
     */
    @JsonCreator
    public SingleTokenAccessPolicySpecifier(
            @JsonProperty("policyType") SingleTokenAccessPolicyType policyType,
            @JsonProperty("requiredClaims") Map<String, String> requiredClaims)
            throws InvalidArgumentsException {
        switch (policyType) {
            case SLHTIBAP:
                if (requiredClaims == null
                        || requiredClaims.isEmpty()
                        || !requiredClaims.containsKey(Claims.ISSUER)
                        || !requiredClaims.containsKey(Claims.SUBJECT))
                    throw new InvalidArgumentsException("Missing ISS and/or SUB claims required to build this policy type");
                this.requiredClaims = requiredClaims;
                break;
            case SLHTAP:
                if (requiredClaims == null
                        || requiredClaims.isEmpty()
                        || !requiredClaims.containsKey(Claims.ISSUER))
                    throw new InvalidArgumentsException("Missing ISS claim required to build this policy type");
                this.requiredClaims = requiredClaims;
                break;
            case STAP:
                if (requiredClaims == null || requiredClaims.isEmpty())
                    throw new InvalidArgumentsException("Empty claims define a public access policy!");
                this.requiredClaims = requiredClaims;
                break;
            case PUBLIC:
                if (requiredClaims != null && !requiredClaims.isEmpty())
                    throw new InvalidArgumentsException("Public access must not have required claims!");
                this.requiredClaims = new HashMap<>();
                break;
            default:
                throw new InvalidArgumentsException("Failed to resolve proper policy type");
        }
        this.policyType = policyType;
    }

    public SingleTokenAccessPolicyType getPolicyType() {
        return policyType;
    }

    public Map<String, String> getRequiredClaims() {
        return requiredClaims;
    }

    /**
     * Enumeration for specifying the policyType of the sample access policy.
     *
     * @author Vasileios Glykantzis (ICOM)
     */
    public enum SingleTokenAccessPolicyType {
        /**
         * SingleLocalHomeTokenIdentityBasedAccessPolicy
         */
        SLHTIBAP,
        /**
         * SingleLocalHomeTokenAccessPolicy
         */
        SLHTAP,
        /**
         * SingleTokenAccessPolicy
         */
        STAP,
        /**
         * Public access policy
         */
        PUBLIC
    }
}
