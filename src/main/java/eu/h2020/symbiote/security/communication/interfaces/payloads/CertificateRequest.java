package eu.h2020.symbiote.security.communication.interfaces.payloads;

import com.fasterxml.jackson.annotation.JsonIgnore;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by Maks on 2017-06-18.
 */
public class CertificateRequest {

    private String username;
    private String password;
    private String clientId;
    private String clientCSR;

    public CertificateRequest() {
        // required by json
    }

    public CertificateRequest(String username, String password, String clientId, String
            clientCSR) throws IOException {
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientCSR = clientCSR;
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

    public String getClientCSR() {
        return clientCSR;
    }

    public void setClientCSR(String clientCSR) {
        this.clientCSR = clientCSR;
    }

    /**
     * @return retrieve the X509 certificate that corresponds to the stored string
     * @throws CertificateException on internal PEM string value to {@link X509Certificate} conversion (e.g. string value empty)
     */
    @JsonIgnore
    public X509Certificate getX509() throws CertificateException {
        if (clientCSR.isEmpty())
            throw new CertificateException("internal PEM certificate is not initialized");
        ECDSAHelper.enableECDSAProvider();
        InputStream stream = new ByteArrayInputStream(this.getClientCSR().getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(stream);
    }
}
