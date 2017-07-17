package eu.h2020.symbiote.security.communication.interfaces.payloads;


import eu.h2020.symbiote.security.commons.Certificate;

/**
 * SymbIoTe AAM's details. Acts as a security entry point.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class AAM {

    private String aamInstanceId = "";
    private String aamAddress = "";
    private String aamInstanceFriendlyName = "";
    private Certificate certificate;

    /**
     * @param aamAddress              Address where the user can reach REST endpoints used in security layer of SymbIoTe
     * @param aamInstanceFriendlyName a label for the end user to be able to identify the login endrypoint
     * @param aamInstanceId           SymbIoTe-unique identifier (the same as the platform instance it is bound to)
     * @param certificate             CA certificate used by the AAM for its users and issued tokens
     */
    public AAM(
            String aamAddress,
            String aamInstanceFriendlyName,
            String aamInstanceId,
            Certificate certificate) {
        this.aamAddress = aamAddress;
        this.aamInstanceFriendlyName = aamInstanceFriendlyName;
        this.aamInstanceId = aamInstanceId;
        this.certificate = certificate;
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
     * @return a label for the end user to be able to identify the login endrypoint
     */
    public String getAamInstanceFriendlyName() {
        return aamInstanceFriendlyName;
    }

    public void setAamInstanceFriendlyName(String aamInstanceFriendlyName) {
        this.aamInstanceFriendlyName = aamInstanceFriendlyName;
    }

    /**
     * @return CA certificate used by the AAM for its users and issued tokens
     */
    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }
}
