package eu.h2020.symbiote.security.accesspolicies.common;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.*;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import io.jsonwebtoken.Claims;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Factory for producing sample access policies.
 *
 * @author Vasileios Glykantzis (ICOM)
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class SingleTokenAccessPolicyFactory {

    private SingleTokenAccessPolicyFactory() {
    }

    /**
     * Create the access policy from a {@link SingleTokenAccessPolicySpecifier SingleTokenAccessPolicySpecifier}.
     *
     * @param specifier the access policy specifier
     * @return the sample access policy
     * @throws InvalidArgumentsException
     */
    public static IAccessPolicy getSingleTokenAccessPolicy(SingleTokenAccessPolicySpecifier specifier) throws
            InvalidArgumentsException {

        switch (specifier.getPolicyType()) {
            case PUBLIC: {
                return new SingleTokenAccessPolicy(specifier.getRequiredClaims());
            }
            case STAP: {
                return new SingleTokenAccessPolicy(specifier.getRequiredClaims());
            }
            case SFTAP: {
                String homePlatformIdentifier = specifier.getRequiredClaims().get(SingleTokenAccessPolicySpecifier.FEDERATION_HOME_PLATFORM_ID);
                String federationIdentifier = specifier.getRequiredClaims().get(SingleTokenAccessPolicySpecifier.FEDERATION_IDENTIFIER_KEY);
                Set<String> federationMembers = new HashSet<>(Integer.parseInt(specifier.getRequiredClaims().get(SingleTokenAccessPolicySpecifier.FEDERATION_SIZE)));
                for (String claimKey : specifier.getRequiredClaims().keySet()) {
                    if (claimKey.startsWith(SingleTokenAccessPolicySpecifier.FEDERATION_MEMBER_KEY_PREFIX))
                        federationMembers.add(specifier.getRequiredClaims().get(claimKey));
                }
                return new SingleFederatedTokenAccessPolicy(federationMembers, homePlatformIdentifier, federationIdentifier);
            }
            case SFHTAP: {
                String federationIdentifier = specifier.getRequiredClaims().get(SingleTokenAccessPolicySpecifier.FEDERATION_IDENTIFIER_KEY);
                Set<String> federationMembers = new HashSet<>(Integer.parseInt(specifier.getRequiredClaims().get(SingleTokenAccessPolicySpecifier.FEDERATION_SIZE)));
                for (String claimKey : specifier.getRequiredClaims().keySet()) {
                    if (claimKey.startsWith(SingleTokenAccessPolicySpecifier.FEDERATION_MEMBER_KEY_PREFIX))
                        federationMembers.add(specifier.getRequiredClaims().get(claimKey));
                }
                return new SingleFederatedHomeTokenAccessPolicy(federationMembers, federationIdentifier);
            }
            case SLHTAP: {
                String platformIdentifier = specifier.getRequiredClaims().get(Claims.ISSUER);
                Map<String, String> filteredClaims = new HashMap<>(specifier.getRequiredClaims());
                filteredClaims.remove(Claims.ISSUER);
                return new SingleLocalHomeTokenAccessPolicy(platformIdentifier, filteredClaims);
            }
            case SLHTIBAP: {
                String platformIdentifier = specifier.getRequiredClaims().get(Claims.ISSUER);
                String username = specifier.getRequiredClaims().get(Claims.SUBJECT);
                Map<String, String> filteredClaims = new HashMap<>(specifier.getRequiredClaims());
                filteredClaims.remove(Claims.ISSUER);
                filteredClaims.remove(Claims.SUBJECT);
                return new SingleLocalHomeTokenIdentityBasedAccessPolicy(platformIdentifier, username,
                        filteredClaims);
            }
            case CHTAP: {
                String platformIdentifier = specifier.getRequiredClaims().get(Claims.ISSUER);
                String clientId = specifier.getRequiredClaims().get(Claims.SUBJECT);
                Map<String, String> filteredClaims = new HashMap<>(specifier.getRequiredClaims());
                filteredClaims.remove(Claims.ISSUER);
                filteredClaims.remove(Claims.SUBJECT);
                return new ComponentHomeTokenAccessPolicy(platformIdentifier, clientId,
                        filteredClaims);
            }
            default: {
                throw new InvalidArgumentsException("The type of the access policy was not recognized");
            }
        }
    }
}
