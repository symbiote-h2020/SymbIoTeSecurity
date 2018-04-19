package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.accesspolicies.common.AccessPolicyType;
import eu.h2020.symbiote.security.accesspolicies.common.IAccessPolicySpecifier;
import eu.h2020.symbiote.security.accesspolicies.common.SingleTokenAccessPolicyFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import io.jsonwebtoken.Claims;
import org.springframework.data.annotation.PersistenceConstructor;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Specifies the sample access policy. It is used by {@link SingleTokenAccessPolicyFactory SingleTokenAccessPolicyFactory}
 * to create the sample access policy POJO.
 *
 * @author Vasileios Glykantzis (ICOM)
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class SingleTokenAccessPolicySpecifier implements IAccessPolicySpecifier {
    public static final String FEDERATION_MEMBER_KEY_PREFIX = "fed_m_";
    public static final String FEDERATION_SIZE = "fed_s";
    public static final String FEDERATION_HOME_PLATFORM_ID = "fed_h";
    public static final String FEDERATION_IDENTIFIER_KEY = "fed_id";
    public static final String DOES_REQUIRE_ALL_LOCAL_TOKENS = "req_loc";
    private final AccessPolicyType policyType;
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
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_TYPE) AccessPolicyType policyType,
            @JsonProperty(SecurityConstants.ACCESS_POLICY_JSON_FIELD_CLAIMS) Map<String, String> requiredClaims)
            throws InvalidArgumentsException {
        switch (policyType) {
            case SLHTIBAP:
                if (requiredClaims == null
                        || !requiredClaims.containsKey(Claims.ISSUER)
                        || !requiredClaims.containsKey(Claims.SUBJECT))
                    throw new InvalidArgumentsException("Missing ISS and/or SUB claims required to build this policy type");
                this.requiredClaims = requiredClaims;
                break;
            case SLHTAP:
                if (requiredClaims == null
                        || !requiredClaims.containsKey(Claims.ISSUER))
                    throw new InvalidArgumentsException("Missing ISS claim required to build this policy type");
                this.requiredClaims = requiredClaims;
                break;
            case SFTAP:
                // initial check of needed fields
                if (requiredClaims == null
                        || !requiredClaims.containsKey(FEDERATION_HOME_PLATFORM_ID)
                        || !requiredClaims.containsKey(FEDERATION_IDENTIFIER_KEY)
                        || !requiredClaims.containsKey(FEDERATION_SIZE)
                        || !requiredClaims.containsKey(DOES_REQUIRE_ALL_LOCAL_TOKENS))
                    throw new InvalidArgumentsException("Missing required federation policy fields required to build this policy type");
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
            case CHTAP:
                if (requiredClaims == null
                        || !requiredClaims.containsKey(Claims.ISSUER)
                        || !requiredClaims.containsKey(Claims.SUBJECT))
                    throw new InvalidArgumentsException("Missing ISS or/and SUB claim required to build this policy type");
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
     * Used to create the specifier for resources offered in federations according to @{@link SingleFederatedTokenAccessPolicy}
     *
     * @param federationIdentifier          which identifies the authorization granting access claim
     * @param federationMembers             identifiers of platforms participating in the federation (including home platform Id)
     * @param localPlatformIdentifier       used to identifiers our local tokens
     * @param requiredClaimsByLocalUsers    used to authorize our local users
     * @param requireAllLocalTokens         requires exchange of platform Home Tokens to FOREIGN Token issued by local AAM with proper claims to pass the policy
     * @throws InvalidArgumentsException
     */
    public SingleTokenAccessPolicySpecifier(String federationIdentifier,
                                            Set<String> federationMembers,
                                            String localPlatformIdentifier,
                                            Map<String, String> requiredClaimsByLocalUsers,
                                            boolean requireAllLocalTokens) throws
            InvalidArgumentsException {
        // required contents check
        if (federationMembers == null
                || federationMembers.isEmpty()
                || localPlatformIdentifier == null
                || localPlatformIdentifier.isEmpty()
                || federationIdentifier == null
                || federationIdentifier.isEmpty()
                || requiredClaimsByLocalUsers == null
                || !federationMembers.contains(localPlatformIdentifier))
            throw new InvalidArgumentsException("Missing federation definition contents required to build this policy type");

        policyType = AccessPolicyType.SFTAP;
        // building the map
        requiredClaims = new HashMap<>(federationMembers.size() + 2);
        requiredClaims.put(FEDERATION_IDENTIFIER_KEY, federationIdentifier);
        requiredClaims.put(FEDERATION_HOME_PLATFORM_ID, localPlatformIdentifier);
        requiredClaims.put(FEDERATION_SIZE, String.valueOf(federationMembers.size()));
        requiredClaims.put(DOES_REQUIRE_ALL_LOCAL_TOKENS, String.valueOf(requireAllLocalTokens));
        int memberNumber = 1;
        for (String member : federationMembers) {
            requiredClaims.put(FEDERATION_MEMBER_KEY_PREFIX + memberNumber, member);
            memberNumber++;
        }
        requiredClaims.putAll(requiredClaimsByLocalUsers);
    }

    /**
     * Used to create the specifier for resources accessable by component HomeToken
     *
     * @param componentId            - id of the component for which access should be granted
     * @param homePlatformIdentifier - platform of the component
     * @throws InvalidArgumentsException
     */
    public SingleTokenAccessPolicySpecifier(String componentId, String homePlatformIdentifier) throws
            InvalidArgumentsException {
        // required contents check
        if (componentId == null
                || componentId.isEmpty()
                || homePlatformIdentifier == null
                || homePlatformIdentifier.isEmpty())
            throw new InvalidArgumentsException("Missing componentId, homePlatformIdentifier or SH required to build this policy type");

        policyType = AccessPolicyType.CHTAP;
        // building the map
        requiredClaims = new HashMap<>(2);
        requiredClaims.put(Claims.ISSUER, homePlatformIdentifier);
        requiredClaims.put(Claims.SUBJECT, componentId);
    }


    public Map<String, String> getRequiredClaims() {
        return requiredClaims;
    }

    @Override
    public AccessPolicyType getPolicyType() {
        return policyType;
    }
}
