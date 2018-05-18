package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Coupon;

public class BarteralAccessRequest {

    private final String clientPlatform;
    private final String resourceId;
    private final Coupon.Type couponType;

    @JsonCreator
    public BarteralAccessRequest(@JsonProperty("clientPlatform") String clientPlatform,
                                 @JsonProperty("resourceId") String resourceId,
                                 @JsonProperty("couponType") Coupon.Type couponType) {
        this.clientPlatform = clientPlatform;
        this.resourceId = resourceId;
        this.couponType = couponType;
    }

    public String getClientPlatform() {
        return clientPlatform;
    }

    public String getResourceId() {
        return resourceId;
    }

    public Coupon.Type getCouponType() {
        return couponType;
    }


}
