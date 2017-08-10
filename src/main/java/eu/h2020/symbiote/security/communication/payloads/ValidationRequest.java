package eu.h2020.symbiote.security.communication.payloads;

/**
 * Class that defines the structure of a payload used to validate credentials over AMQP
 *
 * @author Piotr Kicki (PSNC)
 */
public class ValidationRequest {

    private String tokenString = "";
    private String certificateString = "";

    public ValidationRequest(String tokenString, String certificateString) {
        this.tokenString = tokenString;
        this.certificateString = certificateString;
    }

    public ValidationRequest() {
        // empty payload might appear in communication
    }

    public String getTokenString() {
        return tokenString;
    }

    public void setTokenString(String tokenString) {
        this.tokenString = tokenString;
    }

    public String getCertificateString() {
        return certificateString;
    }

    public void setCertificateString(String certificateString) {
        this.certificateString = certificateString;
    }

}
