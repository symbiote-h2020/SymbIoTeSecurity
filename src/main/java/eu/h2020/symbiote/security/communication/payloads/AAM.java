package eu.h2020.symbiote.security.communication.payloads;


import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;

import java.util.Map;

/**
 * SymbIoTe AAM's details. Acts as a security entry point.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class AAM {

    private String aamInstanceId = "";
    private String aamAddress = "";
    private String aamInstanceFriendlyName = "";
    private Certificate aamCACertificate;
    private Map<String, Certificate> componentCertificates;

    /**
     * @param aamAddress              Address where the user can reach REST endpoints used in security layer of SymbIoTe
     * @param aamInstanceFriendlyName a label for the end user to be able to identify the login endrypoint
     * @param aamInstanceId           SymbIoTe-unique identifier (the same as the platform instance it is bound to)
     * @param aamCACertificate        CA aamCACertificate used by the AAM for its users and issued tokens
     * @param componentCertificates   contains the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public AAM(
            String aamAddress,
            String aamInstanceFriendlyName,
            String aamInstanceId,
            Certificate aamCACertificate, Map<String, Certificate> componentCertificates) {
        this.aamAddress = aamAddress;
        this.aamInstanceFriendlyName = aamInstanceFriendlyName;
        this.aamInstanceId = aamInstanceId;
        this.aamCACertificate = aamCACertificate;
        this.componentCertificates = componentCertificates;
    }

    public AAM() {
        // required by JSON
    }

    /**
     * @return SymbIoTe-unique identifier (the same as the platform instance it is bound to)
     */
    public String getAamInstanceId() {
        return aamInstanceId;
    }

    public void setAamInstanceId(String aamInstanceId) {
        this.aamInstanceId = aamInstanceId;
    }

    /**
     * @return Address where the user can reach REST endpoints used in security layer of SymbIoTe
     */
    public String getAamAddress() {
        return aamAddress;
    }

    public void setAamAddress(String aamAddress) {
        this.aamAddress = aamAddress;
    }

    /**
     * @return a label for the end user to be able to identify the login entry point
     */
    public String getAamInstanceFriendlyName() {
        return aamInstanceFriendlyName;
    }

    public void setAamInstanceFriendlyName(String aamInstanceFriendlyName) {
        this.aamInstanceFriendlyName = aamInstanceFriendlyName;
    }

    /**
     * @return the AAM Certification Authority certificate used by it for its signing its users' and components' certificates as well as the issued tokens
     */
    public Certificate getAamCACertificate() {
        return aamCACertificate;
    }

    public void setAamCACertificate(Certificate aamCACertificate) {
        this.aamCACertificate = aamCACertificate;
    }

    /**
     * @return the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public Map<String, Certificate> getComponentCertificates() {
        return componentCertificates;
    }

    public void setComponentCertificates(Map<String, Certificate> componentCertificates) {
        this.componentCertificates = componentCertificates;
    }
}
