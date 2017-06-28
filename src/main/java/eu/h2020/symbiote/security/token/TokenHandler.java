package eu.h2020.symbiote.security.token;


import eu.h2020.symbiote.security.SecurityHandler;
import eu.h2020.symbiote.security.amqp.LocalAAMOverAMQPClient;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.rest.clients.AAMClient;
import eu.h2020.symbiote.security.rest.clients.CoreAAMClient;
import eu.h2020.symbiote.security.session.AAM;
import io.jsonwebtoken.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

public class TokenHandler {
    private static Log log = LogFactory.getLog(TokenHandler.class);
    private CoreAAMClient coreAAM;
    private LocalAAMOverAMQPClient platformAAMMessageHandler;
    // TODO R3 rework to Map<String,AAM> built using @{@link SecurityHandler#getAvailableAAMs()}
    private HashMap<String, X509Certificate> publicCertificates;

    /**
     * TODO R3 rework so that this is initialized with the Map built using @{@link SecurityHandler#getAvailableAAMs()}, to locate Core AAM one should use {@link eu.h2020.symbiote.security.constants.AAMConstants#AAM_CORE_AAM_INSTANCE_ID}
     */
    public TokenHandler(CoreAAMClient coreAAM, LocalAAMOverAMQPClient platformAAMMessageHandler) {
        this.coreAAM = coreAAM;
        this.platformAAMMessageHandler = platformAAMMessageHandler;
        this.publicCertificates = new HashMap<>();
    }

    public Token requestFederatedCoreToken(Token homeToken) {
        return coreAAM.requestFederatedToken(homeToken);
    }

    /**
     * TODO R3 unify with the method {@link #requestFederatedCoreToken(Token)} so that the user simply puts the coreAAM in this param
     */
    public Token requestFederatedToken(AAM aam, Token coreToken) {
        AAMClient platformAAM = new AAMClient(aam);
        return platformAAM.requestFederatedToken(coreToken);
    }

    /**
     * TODO R3 drop this method and use the reworked {@link #validateForeignPlatformToken(AAM, Token)}
     */
    public ValidationStatus validateCoreToken(Token token) {
        try {
            ValidationStatus status;
            //TODO R3 checkChallengeResponse()
            status = validateToken(token, getCACert(coreAAM));
            if (status != ValidationStatus.VALID)
                return status;
            return checkRevocation(coreAAM, token);
        } catch (CertificateException ex) {
            log.error(ex);
            return ValidationStatus.INVALID_TRUST_CHAIN;
        }
    }

    /**
     * TODO R3 rename to validateToken and drop the aam parameter completely. This method should automatically, using the @{@link SecurityHandler#getAvailableAAMs()} collection and the token's iss value know which AAM to use for validation.
     */
    public ValidationStatus validateForeignPlatformToken(AAM aam, Token token) {
        try {
            AAMClient platformAAM = new AAMClient(aam);
            ValidationStatus status;
            //TODO R3 checkChallengeResponse()
            status = validateToken(token, getCACert(platformAAM));
            if (status != ValidationStatus.VALID)
                return status;
            return checkRevocation(platformAAM, token);
        } catch (CertificateException ex) {
            log.error(ex);
            return ValidationStatus.INVALID_TRUST_CHAIN;
        }
    }


    private ValidationStatus validateToken(Token token, Certificate certificate) {
        try {
            // validate using the claims parser
            Claims claims = Jwts.parser()
                    .setSigningKey(certificate.getPublicKey())
                    .parseClaimsJws(token.getToken()).getBody();
            token.setClaims(claims);
            return ValidationStatus.VALID;
        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
            log.debug(e);
            return ValidationStatus.INVALID_TRUST_CHAIN;
        } catch (ExpiredJwtException e) {
            log.debug(e);
            return ValidationStatus.EXPIRED_TOKEN;
        }
    }

    /**
     * TODO R3 This method should automatically, using the @{@link SecurityHandler#getAvailableAAMs()} collection and the token's iss value know which AAM to use for validation.
     */
    private ValidationStatus checkRevocation(AAMClient aamClient, Token tokenForRevocation) {
        return aamClient.validate(tokenForRevocation);
    }


    /**
     * TODO R3, when we have certificate signing request support in Core AAM we can drop this method completely as @{@link SecurityHandler#getAvailableAAMs()} will provide up-to-date AAM data including the certificates
     */
    private X509Certificate getCACert(AAMClient aamClient) throws CertificateException {
        String url = aamClient.getURL();
        // TODO early  R3 rework to Map<String,AAM> built using @{@link SecurityHandler#getAvailableAAMs()}
        X509Certificate aamX509Certificate = publicCertificates.get(url);
        if (aamX509Certificate == null) {
            aamX509Certificate = aamClient.getAAMCertificate();
            publicCertificates.put(url, aamX509Certificate);
        }
        return aamX509Certificate;
    }

    /**
     * Validates the token using the AMQP connection to the local/internal AAM
     *
     * @param token to be validated
     * @return status of the validation or {@link ValidationStatus#NULL} on error
     */
    public ValidationStatus validateHomeToken(Token token) {
        ValidationStatus validationStatus = ValidationStatus.NULL;
        try {
            validationStatus = ValidationStatus.valueOf(platformAAMMessageHandler
                    .validate(token).getStatus());
        } catch (SecurityHandlerException e) {
            log.error(e);
        }
        return validationStatus;
    }
}

