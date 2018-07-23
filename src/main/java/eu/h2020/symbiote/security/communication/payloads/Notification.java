package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Payload used by BTMs to notify Core BTM about creation and usage of the coupons;
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
//TODO shouldn't it be signed to be sure it's genuine?
public class Notification {
    private final String couponString;
    private final String subject;

    @JsonCreator
    public Notification(@JsonProperty("couponString") String couponString,
                        @JsonProperty("subject") String subject) {
        this.couponString = couponString;
        this.subject = subject;
    }

    public String getCouponString() {
        return couponString;
    }

    public String getSubject() {
        return subject;
    }
}
