package eu.h2020.symbiote.security.communication.payloads;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;

import java.util.Map;

/**
 * SymbIoTe AAM's details. Acts as a security entry point.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class AAM {

    private final String aamInstanceId;
    private final String aamAddress;
    private final String siteLocalAddress;
    private final String aamInstanceFriendlyName;
    private final Certificate aamCACertificate;
    private final Map<String, Certificate> componentCertificates;

    /**
     * @param aamAddress              Address where the user can reach REST endpoints used in security layer of SymbIoTe
     * @param aamInstanceFriendlyName a label for the end user to be able to identify the login endrypoint
     * @param aamInstanceId           SymbIoTe-unique identifier (the same as the platform instance it is bound to)
     * @param siteLocalAddress        Address where the user can reach REST endpoints used in security layer of SymbIoTe in local service net
     * @param aamCACertificate        CA aamCACertificate used by the AAM for its users and issued tokens
     * @param componentCertificates   contains the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    @JsonCreator
    public AAM(
            @JsonProperty("aamAddress") String aamAddress,
            @JsonProperty("aamInstanceFriendlyName") String aamInstanceFriendlyName,
            @JsonProperty("aamInstanceId") String aamInstanceId,
            @JsonProperty("siteLocalAddress") String siteLocalAddress,
            @JsonProperty("aamCACertificate") Certificate aamCACertificate,
            @JsonProperty("componentCertificates") Map<String, Certificate> componentCertificates) {
        this.aamAddress = aamAddress;
        this.aamInstanceFriendlyName = aamInstanceFriendlyName;
        this.aamInstanceId = aamInstanceId;
        this.siteLocalAddress = siteLocalAddress;
        this.aamCACertificate = aamCACertificate;
        this.componentCertificates = componentCertificates;
    }

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
            Certificate aamCACertificate,
            Map<String, Certificate> componentCertificates) {
        this.aamAddress = aamAddress;
        this.aamInstanceFriendlyName = aamInstanceFriendlyName;
        this.aamInstanceId = aamInstanceId;
        this.siteLocalAddress = "";
        this.aamCACertificate = aamCACertificate;
        this.componentCertificates = componentCertificates;
    }


    /**
     * @return SymbIoTe-unique identifier (the same as the platform instance it is bound to)
     */
    public String getAamInstanceId() {
        return aamInstanceId;
    }

    /**
     * @return Address where the user can reach REST endpoints used in security layer of SymbIoTe
     */
    public String getAamAddress() {
        return aamAddress;
    }

    /**
     * @return a label for the end user to be able to identify the login entry point
     */
    public String getAamInstanceFriendlyName() {
        return aamInstanceFriendlyName;
    }

    /**
     * @return the AAM Certification Authority certificate used by it for its signing its users' and components' certificates as well as the issued tokens
     */
    public Certificate getAamCACertificate() {
        return aamCACertificate;
    }

    /**
     * @return the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public Map<String, Certificate> getComponentCertificates() {
        return componentCertificates;
    }

    /**
     * @return Address where the user can reach REST endpoints used in security layer of SymbIoTe in local service net
     */
    public String getSiteLocalAddress() {
        return siteLocalAddress;
    }
}
