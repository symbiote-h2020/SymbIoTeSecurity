package eu.h2020.symbiote.security.commons;

import com.fasterxml.jackson.annotation.JsonIgnore;
import eu.h2020.symbiote.security.helpers.ECDSAHelper;
import org.springframework.data.annotation.Id;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * SymbIoTe certificate with stored PEM value
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class Certificate {

    @Id
    private String certificateString = "";

    /**
     * required by JPA
     */
    public Certificate() {
        // TODO R4 drop this and force immutability in R4
    }

    /**
     * @param certificateString in PEM format
     * @throws CertificateException when the passed PEM certificate is invalid
     */
    public Certificate(String certificateString) throws CertificateException {
        this.setCertificateString(certificateString);
    }

    /**
     * @return retrieve the X509 certificate that corresponds to the stored string
     * @throws CertificateException on internal PEM string value to {@link X509Certificate} conversion (e.g. string value empty)
     */
    @JsonIgnore
    public X509Certificate getX509() throws CertificateException {
        if (certificateString.isEmpty())
            throw new CertificateException("internal PEM certificate is not initialized");
        ECDSAHelper.enableECDSAProvider();
        InputStream stream = new ByteArrayInputStream(this.getCertificateString().getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(stream);
    }

    /**
     * @return in PEM format
     */
    public String getCertificateString() {
        return certificateString;
    }

    /**
     * @param certificateString in PEM format
     */
    public void setCertificateString(String certificateString) throws CertificateException {
        if (certificateString == null) // || certificateString.isEmpty()) // todo R4 enforce this check
            throw new CertificateException("trying to pass empty value");
        // removing carriage return to make the string platform independent
        this.certificateString = certificateString.replace("\r", "");
    }

    @Override
    public String toString() {
        return this.certificateString;
    }
}
