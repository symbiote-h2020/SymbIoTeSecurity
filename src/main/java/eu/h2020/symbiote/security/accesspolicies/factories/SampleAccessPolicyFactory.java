package eu.h2020.symbiote.security.accesspolicies.factories;


import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.SingleLocalHomeTokenAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.SingleLocalHomeTokenIdentityBasedTokenAccessPolicy;
import eu.h2020.symbiote.security.accesspolicies.SingleTokenAccessPolicy;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.util.HashMap;

/**
 * Factory for producing sample access policies.
 *
 * @author Vasileios Glykantzis (ICOM)
 */
public class SampleAccessPolicyFactory {

    public SampleAccessPolicyFactory() {
    }

    /**
     * Create the access policy from a {@link SampleAccessPolicySpecifier SampleAccessPolicySpecifier}.
     *
     * @param specifier the access policy specifier
     * @return the sample access policy
     * @throws InvalidArgumentsException
     */
    public static IAccessPolicy getSampleAccessPolicy(SampleAccessPolicySpecifier specifier)
            throws InvalidArgumentsException {

        switch (specifier.getType()) {
            case STAP: {
                return new SingleTokenAccessPolicy(specifier.getRequiredClaims());
            }
            case SLHTAP: {
                String platformIdentifier = specifier.getRequiredClaims().get("iss");
                return new SingleLocalHomeTokenAccessPolicy(platformIdentifier, specifier.getRequiredClaims());
            }
            case SLHTIBTAP: {
                String platformIdentifier = specifier.getRequiredClaims().get("iss");
                String username = specifier.getRequiredClaims().get("sub");
                return new SingleLocalHomeTokenIdentityBasedTokenAccessPolicy(platformIdentifier, username,
                        specifier.getRequiredClaims());
            }
            case PUBLIC: {
                return new SingleTokenAccessPolicy(new HashMap<>());
            }
            default: throw new InvalidArgumentsException("The type of the sample access policy was not recognized");
        }
    }
}
