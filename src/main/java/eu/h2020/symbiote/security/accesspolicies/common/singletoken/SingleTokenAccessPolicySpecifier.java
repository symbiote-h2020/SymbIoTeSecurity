package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import org.springframework.data.annotation.PersistenceConstructor;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import io.jsonwebtoken.Claims;

/**
 * Specifies the sample access policy. It is used by {@link SingleTokenAccessPolicyFactory SingleTokenAccessPolicyFactory}
 * to create the sample access policy POJO.
 *
 * @author Vasileios Glykantzis (ICOM)
 * @author Mikołaj Dobski (PSNC)
 */
public class SingleTokenAccessPolicySpecifier {
    public static final String FEDERATION_MEMBER_KEY_PREFIX = "fed_m_";
    public static final String FEDERATION_SIZE = "fed_s";
    public static final String FEDERATION_HOME_PLATFORM_ID = "fed_h";
    public static final String FEDERATION_IDENTIFIER_KEY = "fed_id";
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
    @PersistenceConstructor
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
            case SFTAP:
                // initial check of needed fields
                if (requiredClaims == null
                        || requiredClaims.isEmpty()
                        || !requiredClaims.containsKey(FEDERATION_HOME_PLATFORM_ID)
                        || !requiredClaims.containsKey(FEDERATION_IDENTIFIER_KEY)
                        || !requiredClaims.containsKey(FEDERATION_SIZE))
                    throw new InvalidArgumentsException("Missing federation definition contents required to build this policy type");
                // checking if all members are there
                long federationSize = Long.parseLong(requiredClaims.get(FEDERATION_SIZE));
                for (long i = 1; i <= federationSize; i++) {
                    if (!requiredClaims.containsKey(FEDERATION_MEMBER_KEY_PREFIX + i))
                        throw new InvalidArgumentsException("Missing federation member required to build this policy type");
                }
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

    /**
     * Used to create the specifier for resources offered in federations
     *
     * @param federationMembers      identifiers of platforms participating in the federation (including home platform Id)
     * @param homePlatformIdentifier used to authorize users with home tokens from the given platform
     * @param federationIdentifier   which identifies the authorization granting access claim
     * @throws InvalidArgumentsException
     */
    public SingleTokenAccessPolicySpecifier(Set<String> federationMembers, String homePlatformIdentifier, String federationIdentifier) throws
            InvalidArgumentsException {
        // required contents check
        if (federationMembers == null
                || federationMembers.isEmpty()
                || homePlatformIdentifier == null
                || homePlatformIdentifier.isEmpty()
                || federationIdentifier == null
                || federationIdentifier.isEmpty()
                || !federationMembers.contains(homePlatformIdentifier))
            throw new InvalidArgumentsException("Missing federation definition contents required to build this policy type");

        policyType = SingleTokenAccessPolicyType.SFTAP;
        // building the map
        requiredClaims = new HashMap<>(federationMembers.size() + 2);
        requiredClaims.put(FEDERATION_IDENTIFIER_KEY, federationIdentifier);
        requiredClaims.put(FEDERATION_HOME_PLATFORM_ID, homePlatformIdentifier);
        requiredClaims.put(FEDERATION_SIZE, String.valueOf(federationMembers.size()));
        int memberNumber = 1;
        for (String member : federationMembers) {
            requiredClaims.put(FEDERATION_MEMBER_KEY_PREFIX + memberNumber, member);
            memberNumber++;
        }
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
         * SingleFederatedTokenAccessPolicy
         */
        SFTAP,
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
