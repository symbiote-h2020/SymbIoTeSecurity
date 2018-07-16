package eu.h2020.symbiote.security.commons.enums;

public enum CouponValidationStatus {
    /**
     * it is valid
     */
    VALID,
    /**
     * coupon was already consumed
     */
    CONSUMED_COUPON,
    /**
     * coupon was revoked
     */
    REVOKED_COUPON,
    /**
     * coupon is not in Core database
     */
    COUPON_NOT_REGISTERED,
    /**
     * coupon is different, than this saved in repository
     */
    DB_MISMATCH,
    /**
     * unknown status of the coupon
     */
    UNKNOWN,

}
