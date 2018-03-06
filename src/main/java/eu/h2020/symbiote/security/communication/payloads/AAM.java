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
 *
 * @apiNote due to keeping API compliance the getters where not renamed.
 */
public class AAM {

    private final String aamInstanceId;
    private final String aamAddress;
    private final String siteLocalAddress;
    private final String aamInstanceFriendlyName;
    private final Certificate aamCACertificate;
    private final Map<String, Certificate> componentCertificates;

    /**
     * @param externalAddress                        address where the AAM is available from the Internet e.g. the Core, Platforms and SmartSpaces' gateways
     * @param siteLocalAddress                       address where the AAM is available for clients residing in the same network that the server (e.g. local WiFi of a smart space)
     * @param instanceIdentifier                     identifier of this AAM (the same as the platform / smart space instance it is bound to)
     * @param instanceFriendlyName                   a label for the end users to be able to identify this platform / smart space
     * @param localCertificationAuthorityCertificate the Certification Authority certificate that this AAM uses to sign its clients certificates and tokens
     * @param componentCertificates                  contains the certificates signed by this AAM for components that belong to the same platform / smart space, used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    @JsonCreator
    public AAM(
            @JsonProperty("aamAddress") String externalAddress,
            @JsonProperty("siteLocalAddress") String siteLocalAddress,
            @JsonProperty("aamInstanceId") String instanceIdentifier,
            @JsonProperty("aamInstanceFriendlyName") String instanceFriendlyName,
            @JsonProperty("aamCACertificate") Certificate localCertificationAuthorityCertificate,
            @JsonProperty("componentCertificates") Map<String, Certificate> componentCertificates) {
        this.aamAddress = externalAddress;
        this.aamInstanceFriendlyName = instanceFriendlyName;
        this.aamInstanceId = instanceIdentifier;
        this.siteLocalAddress = siteLocalAddress;
        this.aamCACertificate = localCertificationAuthorityCertificate;
        this.componentCertificates = componentCertificates;
    }

    /**
     * @param externalAddress                        Address where the AAM is available from the Internet e.g. the Core, Platforms and SmartSpaces' gateways
     * @param instanceIdentifier                     identifier of this AAM (the same as the platform / smart space instance it is bound to)
     * @param instanceFriendlyName                   a label for the end users to be able to identify this platform / smart space
     * @param localCertificationAuthorityCertificate the Certification Authority certificate that this AAM uses to sign its clients certificates and tokens
     * @param componentCertificates                  contains the certificates signed by this AAM for components that belong to the same platform / smart space, used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public AAM(
            String externalAddress,
            String instanceIdentifier,
            String instanceFriendlyName,
            Certificate localCertificationAuthorityCertificate,
            Map<String, Certificate> componentCertificates) {
        this(externalAddress,
                "", // useful only by smart spaces
                instanceIdentifier,
                instanceFriendlyName,
                localCertificationAuthorityCertificate,
                componentCertificates);
    }

    /**
     * @return identifier of this AAM (the same as the platform / smart space instance it is bound to)
     */
    public String getAamInstanceId() {
        return aamInstanceId;
    }

    /**
     * @return address where the AAM is available from the Internet e.g. the Core, Platforms and SmartSpaces' gateways
     */
    public String getAamAddress() {
        return aamAddress;
    }

    /**
     * @return a label for the end users to be able to identify this platform / smart space
     */
    public String getAamInstanceFriendlyName() {
        return aamInstanceFriendlyName;
    }

    /**
     * @return the Certification Authority certificate that this AAM uses to sign its clients certificates and tokens
     */
    public Certificate getAamCACertificate() {
        return aamCACertificate;
    }

    /**
     * @return contains the certificates signed by this AAM for components that belong to the same platform / smart space, used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public Map<String, Certificate> getComponentCertificates() {
        return componentCertificates;
    }

    /**
     * @return address where the AAM is available for clients residing in the same network that the server (e.g. local WiFi of a smart space)
     */
    public String getSiteLocalAddress() {
        return siteLocalAddress;
    }
}
