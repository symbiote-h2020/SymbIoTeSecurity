package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Coupon;

public class BarteredAccessRequest {

    private final String clientPlatform;
    private final String federationId;
    private final String resourceId;
    private final Coupon.Type couponType;

    @JsonCreator
    public BarteredAccessRequest(@JsonProperty("clientPlatform") String clientPlatform,
                                 @JsonProperty("federationId") String federationId,
                                 @JsonProperty("resourceId") String resourceId,
                                 @JsonProperty("couponType") Coupon.Type couponType) {
        this.clientPlatform = clientPlatform;
        this.federationId = federationId;
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

    public String getFederationId() {
        return federationId;
    }
}
