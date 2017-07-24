package eu.h2020.symbiote.security.communication.interfaces.payloads;

import javax.crypto.SealedObject;
import java.security.SignedObject;

/**
 * Utility class for containing the challenge payload to be further encapsulated in a {@link SealedObject} challenge.
 *
 * @author Daniele Caldarola (CNIT)
 */
public class ResponsePayload {


    private SignedObject signedHash;
    private Long timestamp2;

    public ResponsePayload(SignedObject signedHash, Long timestamp1) {
        this.signedHash = signedHash;
        this.timestamp2 = timestamp1;
    }

    public SignedObject getSignedHash() {
        return signedHash;
    }

    public void setSignedHash(SignedObject signedHash) {
        this.signedHash = signedHash;
    }

    public Long getTimestamp2() {
        return timestamp2;
    }

    public void setTimestamp2(Long timestamp2) {
        this.timestamp2 = timestamp2;
    }

}
