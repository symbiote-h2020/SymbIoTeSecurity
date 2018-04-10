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
     * unknown status of the coupon
     */
    UNKNOWN,


}
