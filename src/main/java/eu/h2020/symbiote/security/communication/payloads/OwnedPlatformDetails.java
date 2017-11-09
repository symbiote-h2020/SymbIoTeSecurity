package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;

import java.util.Map;

/**
 * SymbIoTe-enabled IoT platform instance details registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class OwnedPlatformDetails {

    private final String platformInstanceId;
    private final String platformInterworkingInterfaceAddress;
    private final String platformInstanceFriendlyName;
    private final Certificate platformAAMCertificate;
    private final Map<String, Certificate> componentCertificates;

    /**
     * @param platformInstanceId                   SymbIoTe-unique platform identifier
     * @param platformInterworkingInterfaceAddress Address where the Platform exposes its Interworking Interface
     * @param platformInstanceFriendlyName         a label for the end user to be able to identify the login endrypoint
     * @param platformAAMCertificate               the platform's AM CA Certificate
     * @param componentCertificates                the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    @JsonCreator
    public OwnedPlatformDetails(@JsonProperty("platformInstanceId") String platformInstanceId,
                                @JsonProperty("platformInterworkingInterfaceAddress") String platformInterworkingInterfaceAddress,
                                @JsonProperty("platformInstanceFriendlyName") String platformInstanceFriendlyName,
                                @JsonProperty("platformAAMCertificate") Certificate platformAAMCertificate,
                                @JsonProperty("componentCertificates") Map<String, Certificate> componentCertificates) {
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

    /**
     * @return Address where the Platform exposes its Interworking Interface
     */
    public String getPlatformInterworkingInterfaceAddress() {
        return platformInterworkingInterfaceAddress;
    }

    /**
     * @return a label for the end user to be able to identify the login endrypoint
     */
    public String getPlatformInstanceFriendlyName() {
        return platformInstanceFriendlyName;
    }

    /**
     * @return the platform's AM CA Certificate
     */
    public Certificate getPlatformAAMCertificate() {
        return platformAAMCertificate;
    }

    /**
     * @return the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public Map<String, Certificate> getComponentCertificates() {
        return componentCertificates;
    }
}
