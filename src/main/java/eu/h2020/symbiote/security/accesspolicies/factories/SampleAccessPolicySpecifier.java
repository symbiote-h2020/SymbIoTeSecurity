package eu.h2020.symbiote.security.accesspolicies.factories;

import java.util.HashMap;
import java.util.Map;

/**
 * Specifies the sample access policy. It is used by {@link SampleAccessPolicyFactory SampleAccessPolicyFactory}
 * to create the sample access policy POJO.
 *
 * @author Vasileios Glykantzis (ICOM)
 */
public class SampleAccessPolicySpecifier {
    private SampleAccessPolicyType type;
    private Map<String, String> requiredClaims = new HashMap<>();

    public SampleAccessPolicySpecifier() {
    }

    /**
     * Constructor of SampleAccessPolicySpecifier
     *
     * @param type              type of the sample access policy
     * @param requiredClaims    map with all the claims that need to be contained in a single token to satisfy the
     *                          sample access policy
     */
    public SampleAccessPolicySpecifier(SampleAccessPolicyType type, Map<String, String> requiredClaims) {
        this.type = type;
        this.requiredClaims = requiredClaims;
    }

    public SampleAccessPolicyType getType() { return type; }
    public void setType(SampleAccessPolicyType type) { this.type = type; }

    public Map<String, String> getRequiredClaims() { return requiredClaims; }
    public void setRequiredClaims(Map<String, String> requiredClaims) { this.requiredClaims = requiredClaims; }
}
