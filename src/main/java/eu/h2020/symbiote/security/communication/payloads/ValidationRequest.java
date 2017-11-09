package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Class that defines the structure of a payload used to validate credentials over AMQP
 *
 * @author Piotr Kicki (PSNC)
 */
public class ValidationRequest {

    private final String token;
    private final String clientCertificate;
    private final String clientCertificateSigningAAMCertificate;
    private final String foreignTokenIssuingAAMCertificate;

    @JsonCreator
    public ValidationRequest(@JsonProperty("token") String token,
                             @JsonProperty("clientCertificate") String clientCertificate,
                             @JsonProperty("clientCertificateSigningAAMCertificate") String clientCertificateSigningAAMCertificate,
                             @JsonProperty("foreignTokenIssuingAAMCertificate") String foreignTokenIssuingAAMCertificate) {
        this.token = token;
        this.clientCertificate = clientCertificate;
        this.clientCertificateSigningAAMCertificate = clientCertificateSigningAAMCertificate;
        this.foreignTokenIssuingAAMCertificate = foreignTokenIssuingAAMCertificate;
    }

    public String getToken() {
        return token;
    }

    public String getClientCertificate() {
        return clientCertificate;
    }

    public String getClientCertificateSigningAAMCertificate() {
        return clientCertificateSigningAAMCertificate;
    }

    public String getForeignTokenIssuingAAMCertificate() {
        return foreignTokenIssuingAAMCertificate;
    }
}
