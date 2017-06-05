package eu.h2020.symbiote.security.enums;

/**
 * Enumeration used as outcome of certificate/token validation procedure
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Pietro Tedeschi (CNIT)
 */
public enum ValidationStatus {
    /**
     * it is valid
     */
    VALID,

    /**
     * it has reached its end of life
     */
    EXPIRED_ISSUER_CERTIFICATE,

    /**
     * it has reached its end of life
     */
    EXPIRED_SUBJECT_CERTIFICATE,

    /**
     * it has reached its end of life
     */
    EXPIRED_TOKEN,

    /**
     * issuer Public Key was revoked
     */
    REVOKED_IPK,

    /**
     * subject Public Key was revoked
     */
    REVOKED_SPK,

    /**
     * token was revoked
     */
    REVOKED_TOKEN,

    /**
     * when the validation was attempted in a Token's foreign AAM
     * and the AAM failed to relay the validation to the Token's home AAM
     */
    WRONG_AAM,

    /**
     * when e.g. the signature verification failed (e.g. the chain from the certificate doesn't match)
     */
    INVALID_TRUST_CHAIN,

    /**
     * when the validation procedure failed for whatever reason (e.g. internal server error)
     */
    UNKNOWN,

    /**
     * uninitialized value of this enum
     */
    NULL
}
