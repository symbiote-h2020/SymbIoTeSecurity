package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Coupon;

/**
 * SymbIoTe BTM's coupon validation details.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class CouponValidity {

    private final Status status;
    private final Coupon.Type type;
    private final long remainingUsages;
    private final long remainingTime;

    @JsonCreator
    public CouponValidity(@JsonProperty("status") Status status,
                          @JsonProperty("type") Coupon.Type type,
                          @JsonProperty("remainingUsages") long remainingUsages,
                          @JsonProperty("remainingTime") long remainingTime) {
        this.status = status;
        this.type = type;
        this.remainingUsages = remainingUsages;
        this.remainingTime = remainingTime;
    }

    public Status getStatus() {
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

    public enum Status {
        VALID,
        INVALID
    }
}
