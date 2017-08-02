package eu.h2020.symbiote.security.communication.interfaces.payloads;

/**
 * Class that defines structure of payload needed to get client certificate
 * @author Maks Marcinowski (PSNC)
 */
public class CertificateRequest {

    private String username;
    private String password;
    private String clientId;
    private String clientCSRinPEMFormat;

    public CertificateRequest() {
        // required by json
    }


    /**
     * @param username             user's name
     * @param password             user's password
     * @param clientId             id of the client
     * @param clientCSRinPEMFormat certificate signing request given in PEM format
     */
    public CertificateRequest(String username, String password, String clientId, String
            clientCSRinPEMFormat) {
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientCSRinPEMFormat = clientCSRinPEMFormat;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientCSRinPEMFormat() { return clientCSRinPEMFormat; }

    public void setClientCSRinPEMFormat(String clientCSRinPEMFormat) {
        this.clientCSRinPEMFormat = clientCSRinPEMFormat;
    }
}
