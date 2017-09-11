package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Class that defines structure of payload needed to get client certificate
 *
 * @author Maks Marcinowski (PSNC)
 */
public class CertificateRequest {

    private String username;
    private String password;
    private String clientId;
    private String clientCSRinPEMFormat;

    /**
     * @param username             user's name
     * @param password             user's password
     * @param clientId             id of the client
     * @param clientCSRinPEMFormat certificate signing request given in PEM format
     */
    @JsonCreator
    public CertificateRequest(@JsonProperty("username") String username,
                              @JsonProperty("password") String password,
                              @JsonProperty("clientId") String clientId,
                              @JsonProperty("clientCSRinPEMFormat") String clientCSRinPEMFormat) {
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientCSRinPEMFormat = clientCSRinPEMFormat;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientCSRinPEMFormat() {
        return clientCSRinPEMFormat;
    }
}
