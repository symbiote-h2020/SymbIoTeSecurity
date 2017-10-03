package eu.h2020.symbiote.security.accesspolicies.common.singletoken;

import eu.h2020.symbiote.security.accesspolicies.IAccessPolicy;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;
import eu.h2020.symbiote.security.handler.ISecurityHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.cert.CertificateException;
import java.util.*;
import java.util.Map.Entry;

import static eu.h2020.symbiote.security.helpers.CryptoHelper.illegalSign;

/**
 * SymbIoTe Access Policy that needs to be satisfied by a single Token issued by local AAM for a particular user
 *
 * @author Jakub Toczek (PSNC)
 */
public class ComponentHomeTokenAccessPolicy implements IAccessPolicy {

    private static Log log = LogFactory.getLog(ComponentHomeTokenAccessPolicy.class);
    private final String platformIdentifier;
    private final String componentId;
    private final ISecurityHandler securityHandler;
    private String ipk = "";
    private String spk = "";
    private Map<String, String> requiredClaims = new HashMap<>();

    /**
     * Creates a new access policy object
     *
     * @param platformIdentifier so that HOME tokens are properly identified
     * @param componentId        the component for which should have access to the resource
     * @param requiredClaims     optional map with all other claims that need to be contained in a single token to satisfy the policy
     */
    public ComponentHomeTokenAccessPolicy(String platformIdentifier, String componentId, Map<String, String> requiredClaims, ISecurityHandler securityHandler) throws
            InvalidArgumentsException {
        this.securityHandler = securityHandler;
        if (platformIdentifier == null || platformIdentifier.isEmpty())
            throw new InvalidArgumentsException("Platform identifier must not be null/empty!");
        this.platformIdentifier = platformIdentifier;
        if (componentId == null || componentId.isEmpty())
            throw new InvalidArgumentsException("Username must not be null/empty!");
        this.componentId = componentId;
        if (requiredClaims != null)
            this.requiredClaims = requiredClaims;
    }


    @Override
    public Set<Token> isSatisfiedWith(Set<Token> authorizationTokens) {
        Set<Token> validTokens = new HashSet<>();
        if (this.ipk.isEmpty()) {
            try {
                this.ipk = Base64.getEncoder().encodeToString(
                        this.securityHandler.getComponentCertificate(SecurityConstants.AAM_COMPONENT_NAME, platformIdentifier).getX509().getPublicKey().getEncoded());
            } catch (CertificateException e) {
                log.error("Error occured receiving ipk");
                return validTokens;
            }
        }
        if (this.spk.isEmpty()) {
            try {
                this.spk = Base64.getEncoder().encodeToString(
                        this.securityHandler.getComponentCertificate(componentId, platformIdentifier).getX509().getPublicKey().getEncoded());
            } catch (CertificateException e) {
                log.error("Error occured receiving spk");
                return validTokens;
            }
        }
        // presume that none of the tokens could satisfy the policy

        // trying to find token satisfying this policy
        for (Token token : authorizationTokens) {
            //verify if token
            if (token.getType().equals(Token.Type.HOME) // is HOME ttyp
                    && token.getClaims().getIssuer().equals(platformIdentifier) // is issued by this/local (platform) AAM
                    && token.getClaims().getSubject().split(illegalSign)[1].equals(platformIdentifier) //for it's component
                    && token.getClaims().getSubject().split(illegalSign)[0].equals(componentId) // for the given component
                    && token.getClaims().get("ipk").equals(this.ipk)    //checking ipk
                    && token.getClaims().get("spk").equals(this.spk)    //checking spk
                    && isSatisfiedWith(token)) { // and if the token satisfies the general policy idea
                validTokens.add(token);
                return validTokens;
            }
        }

        return validTokens;
    }

    private boolean isSatisfiedWith(Token token) {
        // empty access policy is satisfied by any token
        if (requiredClaims.isEmpty())
            return true;

        // need to verify that all the required claims are in the token
        for (Entry<String, String> requiredClaim : requiredClaims.entrySet()) {
            // try to find requiredClaim in token attributes
            String claimValue = (String) token.getClaims().get(requiredClaim.getKey());
            // missing claim causes failed authorization
            if (claimValue == null)
                return false;
            // wrong value of the claim also causes failed authorization
            if (!requiredClaim.getValue().equals(claimValue))
                return false;
        }
        // token passes the satisfaction procedure
        return true;
    }
}
