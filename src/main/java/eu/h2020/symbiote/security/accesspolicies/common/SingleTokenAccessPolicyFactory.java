package eu.h2020.symbiote.security.accesspolicies.common;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleLocalHomeTokenAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleLocalHomeTokenIdentityBasedAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.common.singletoken.SingleTokenAccessPolicySpecifier;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import io.jsonwebtoken.Claims;

import java.util.HashMap;
import java.util.Map;

/**
 * Factory for producing sample access policies.
 *
 * @author Vasileios Glykantzis (ICOM)
 * @author Mikołaj Dobski (PSNC)
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
    public static IAccessPolicy getSingleTokenAccessPolicy(SingleTokenAccessPolicySpecifier specifier)
            throws InvalidArgumentsException {

        switch (specifier.getPolicyType()) {
            case PUBLIC: {
                return new SingleTokenAccessPolicy(specifier.getRequiredClaims());
            }
            case STAP: {
                return new SingleTokenAccessPolicy(specifier.getRequiredClaims());
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
            default:
                throw new InvalidArgumentsException("The type of the access policy was not recognized");
        }
    }
}
