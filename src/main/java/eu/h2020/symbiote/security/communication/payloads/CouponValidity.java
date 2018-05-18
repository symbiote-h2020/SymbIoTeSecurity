package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Coupon;
import eu.h2020.symbiote.security.commons.enums.CouponValidationStatus;

/**
 * SymbIoTe BTM's coupon validation details.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class CouponValidity {

    private final CouponValidationStatus status;
    private final Coupon.Type type;
    private final long remainingUsages;
    private final long remainingTime;

    @JsonCreator
    public CouponValidity(@JsonProperty("status") CouponValidationStatus status,
                          @JsonProperty("type") Coupon.Type type,
                          @JsonProperty("remainingUsages") long remainingUsages,
                          @JsonProperty("remainingTime") long remainingTime) {
        this.status = status;
        this.type = type;
        this.remainingUsages = remainingUsages;
        this.remainingTime = remainingTime;
    }

    public CouponValidationStatus getStatus() {
        return status;
    }

    public Coupon.Type getType() {
        return type;
    }

    public long getRemainingUsages() {
        return remainingUsages;
    }

    public long getRemainingTime() {
        return remainingTime;
    }
}
