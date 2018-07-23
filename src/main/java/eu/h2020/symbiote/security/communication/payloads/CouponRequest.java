package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Coupon;

public class CouponRequest {

    private final Coupon.Type couponType;
    private final String federationId;
    private final String platformId;
    private final SecurityRequest securityRequest;

    @JsonCreator
    public CouponRequest(@JsonProperty("couponType") Coupon.Type couponType,
                         @JsonProperty("federationId") String federationId,
                         @JsonProperty("platformId") String platformId,
                         @JsonProperty("securityRequest") SecurityRequest securityRequest) {
        this.couponType = couponType;
        this.federationId = federationId;
        this.platformId = platformId;
        this.securityRequest = securityRequest;
    }

    public Coupon.Type getCouponType() {
        return couponType;
    }

    public String getPlatformId() {
        return platformId;
    }

    public SecurityRequest getSecurityRequest() {
        return securityRequest;
    }

    public String getFederationId() {
        return federationId;
    }
}
