package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;

import java.util.HashMap;
import java.util.Map;

/**
 * SymbIoTe-enabled IoT platform instance details registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class OwnedPlatformDetails {

    private String platformInstanceId = "";
    private String platformInterworkingInterfaceAddress = "";
    private String platformInstanceFriendlyName = "";
    private Certificate platformAAMCertificate = new Certificate();
    private Map<String, Certificate> componentCertificates = new HashMap<>();

    public OwnedPlatformDetails() {
        // for Jackson JSON
    }

    /**
     * @param platformInstanceId                   SymbIoTe-unique platform identifier
     * @param platformInterworkingInterfaceAddress Address where the Platform exposes its Interworking Interface
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login endrypoint
     * @param platformAAMCertificate               the platform's AM CA Certificate
     * @param componentCertificates                the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public OwnedPlatformDetails(String platformInstanceId,
                                String platformInterworkingInterfaceAddress,
                                String platformInstanceFriendlyName,
                                Certificate platformAAMCertificate,
                                Map<String, Certificate> componentCertificates) {
        this.platformInstanceId = platformInstanceId;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
        this.platformAAMCertificate = platformAAMCertificate;
        this.componentCertificates = componentCertificates;
    }

    /**
     * @return SymbIoTe-unique platform identifier
     */
    public String getPlatformInstanceId() {
        return platformInstanceId;
    }

    public void setPlatformInstanceId(String platformInstanceId) {
        this.platformInstanceId = platformInstanceId;
    }

    /**
     * @return Address where the Platform exposes its Interworking Interface
     */
    public String getPlatformInterworkingInterfaceAddress() {
        return platformInterworkingInterfaceAddress;
    }

    public void setPlatformInterworkingInterfaceAddress(String platformInterworkingInterfaceAddress) {
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
    }

    /**
     * @return a label for the end user to be able to identify the login endrypoint
     */
    public String getPlatformInstanceFriendlyName() {
        return platformInstanceFriendlyName;
    }

    public void setPlatformInstanceFriendlyName(String platformInstanceFriendlyName) {
        this.platformInstanceFriendlyName = platformInstanceFriendlyName;
    }

    /**
     * @return the platform's AM CA Certificate
     */
    public Certificate getPlatformAAMCertificate() {
        return platformAAMCertificate;
    }

    public void setPlatformAAMCertificate(Certificate platformAAMCertificate) {
        this.platformAAMCertificate = platformAAMCertificate;
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
