package eu.h2020.symbiote.security.communication.interfaces.payloads;

import java.security.SignedObject;
import java.util.Set;

/**
 * Utility class for containing the challenge payload in the challenge response procedure.
 *
 * @author Daniele Caldarola (CNIT)
 */
public class ApplicationChallenge {

    private Set<SignedObject> signedHashesSet;
    private Long timestamp1;

    public ApplicationChallenge(Set<SignedObject> signatureSet, Long timestamp1) {
        this.signedHashesSet = signatureSet;
        this.timestamp1 = timestamp1;
    }

    public Set<SignedObject> getSignedHashesSet() {
        return signedHashesSet;
    }

    public void setSignedHashesSet(Set<SignedObject> signedHashesSet) {
        this.signedHashesSet = signedHashesSet;
    }

    public Long getTimestamp1() {
        return timestamp1;
    }

    public void setTimestamp1(Long timestamp1) {
        this.timestamp1 = timestamp1;
    }
}