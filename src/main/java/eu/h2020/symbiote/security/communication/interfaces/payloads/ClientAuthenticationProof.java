package eu.h2020.symbiote.security.communication.interfaces.payloads;

import java.security.Signature;
import java.util.Set;

/**
 * Payload sent to the service to proof authorization tokens ownership rights by the client.
 * TODO @Daniele
 */
public class ClientAuthenticationProof {
    public final long timestamp;
    public final Set<Signature> signatures;

    public ClientAuthenticationProof(long timestamp, Set<Signature> signatures) {
        this.timestamp = timestamp;
        this.signatures = signatures;
    }
}
