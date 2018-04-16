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
     * coupon issued by us is not in database
     */
    COUPON_NOT_IN_DB,
    /**
     * unknown status of the coupon
     */
    UNKNOWN,


}
