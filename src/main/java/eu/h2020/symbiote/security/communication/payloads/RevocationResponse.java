package eu.h2020.symbiote.security.communication.payloads;

import org.springframework.http.HttpStatus;

/**
 * Describes revocation payload.
 *
 * @author Jakub Toczek (PSNC)
 */
public class RevocationResponse {
    private boolean isRevoked = false;
    private HttpStatus status;

    public RevocationResponse() {
        // used by serializer
    }

    public RevocationResponse(boolean isRevoked, HttpStatus status) {
        this.isRevoked = isRevoked;
        this.status = status;
    }

    public boolean isRevoked() {
        return isRevoked;
    }

    public void setRevoked(boolean revoked) {
        isRevoked = revoked;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public void setStatus(HttpStatus status) {
        this.status = status;
    }
}