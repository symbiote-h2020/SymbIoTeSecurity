package eu.h2020.symbiote.security.communication.payloads;

/**
 * Class that defines the structure of a payload used to validate credentials over AMQP
 *
 * @author Piotr Kicki (PSNC)
 */
public class ValidationRequest {

    private String token = "";
    private String clientCertificate = "";
    private String clientCertificateSigningAAMCertificate = "";
    private String foreignTokenIssuingAAMCertificate = "";

    public ValidationRequest(String token, String clientCertificate, String clientCertificateSigningAAMCertificate, String foreignTokenIssuingAAMCertificate) {
        this.token = token;
        this.clientCertificate = clientCertificate;
        this.clientCertificateSigningAAMCertificate = clientCertificateSigningAAMCertificate;
        this.foreignTokenIssuingAAMCertificate = foreignTokenIssuingAAMCertificate;
    }

    public ValidationRequest() {
        // empty payload might appear in communication
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getClientCertificate() {
        return clientCertificate;
    }

    public void setClientCertificate(String clientCertificate) {
        this.clientCertificate = clientCertificate;
    }

    public String getClientCertificateSigningAAMCertificate() {
        return clientCertificateSigningAAMCertificate;
    }

    public void setClientCertificateSigningAAMCertificate(String clientCertificateSigningAAMCertificate) {
        this.clientCertificateSigningAAMCertificate = clientCertificateSigningAAMCertificate;
    }

    public String getForeignTokenIssuingAAMCertificate() {
        return foreignTokenIssuingAAMCertificate;
    }

    public void setForeignTokenIssuingAAMCertificate(String foreignTokenIssuingAAMCertificate) {
        this.foreignTokenIssuingAAMCertificate = foreignTokenIssuingAAMCertificate;
    }
}
