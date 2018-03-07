package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;

import java.util.Map;

/**
 * SymbIoTe-enabled IoT service instance details registered in the Core AAM.
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class OwnedService {

    private final String serviceInstanceId;
    private final String instanceFriendlyName;
    private final ServiceType serviceType;
    private final String platformInterworkingInterfaceAddress;
    private final String externalAddress;
    private final boolean exposingSiteLocalAddress;
    private final String siteLocalAddress;
    private final Certificate serviceAAMCertificate;
    private final Map<String, Certificate> componentCertificates;

    /**
     * @param serviceInstanceId                    SymbIoTe-unique service identifier
     * @param instanceFriendlyName                 a label for the end user to be able to identify the login endrypoint
     * @param serviceType                          type of the owned service (Platform, Smart Space)
     * @param platformInterworkingInterfaceAddress Address where the Platform exposes its Interworking Interface
     * @param externalAddress                      address where the Smart Space AAM is available from the Internet
     * @param exposingSiteLocalAddress             should siteLocalAddress be exposed
     * @param siteLocalAddress                     address where the Smart Space AAM is available for clients residing in the same network that the server (e.g. local WiFi of a smart space)
     * @param serviceAAMCertificate                the service's AAM CA Certificate
     * @param componentCertificates                the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    @JsonCreator
    public OwnedService(@JsonProperty("serviceInstanceId") String serviceInstanceId,
                        @JsonProperty("instanceFriendlyName") String instanceFriendlyName,
                        @JsonProperty("serviceType") ServiceType serviceType,
                        @JsonProperty("platformInterworkingInterfaceAddress") String platformInterworkingInterfaceAddress,
                        @JsonProperty("externalAddress") String externalAddress,
                        @JsonProperty("exposingSiteLocalAddress") boolean exposingSiteLocalAddress,
                        @JsonProperty("siteLocalAddress") String siteLocalAddress,
                        @JsonProperty("serviceAAMCertificate") Certificate serviceAAMCertificate,
                        @JsonProperty("componentCertificates") Map<String, Certificate> componentCertificates) {
        this.serviceInstanceId = serviceInstanceId;
        this.platformInterworkingInterfaceAddress = platformInterworkingInterfaceAddress;
        this.instanceFriendlyName = instanceFriendlyName;
        this.externalAddress = externalAddress;
        this.exposingSiteLocalAddress = exposingSiteLocalAddress;
        this.siteLocalAddress = siteLocalAddress;
        this.serviceAAMCertificate = serviceAAMCertificate;
        this.componentCertificates = componentCertificates;
        this.serviceType = serviceType;
    }

    /**
     * @return type of the owned service (Platform, Smart Space)
     */
    public ServiceType getServiceType() {
        return serviceType;
    }

    /**
     * @return address where the Smart Space AAM is available from the Internet
     */
    public String getExternalAddress() {
        return externalAddress;
    }

    /**
     * @return should siteLocalAddress be exposed
     */
    public boolean isExposingSiteLocalAddress() {
        return exposingSiteLocalAddress;
    }

    /**
     * @return address where the Smart Space AAM is available for clients residing in the same network that the server (e.g. local WiFi of a smart space)
     */
    public String getSiteLocalAddress() {
        return siteLocalAddress;
    }

    /**
     * @return SymbIoTe-unique service identifier
     */
    public String getServiceInstanceId() {
        return serviceInstanceId;
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
    public String getInstanceFriendlyName() {
        return instanceFriendlyName;
    }

    /**
     * @return the service's AM CA Certificate
     */
    public Certificate getServiceAAMCertificate() {
        return serviceAAMCertificate;
    }

    /**
     * @return the certificates used by SymbIoTe components for @{@link MutualAuthenticationHelper#isServiceResponseVerified(String, Certificate)}
     */
    public Map<String, Certificate> getComponentCertificates() {
        return componentCertificates;
    }

    public enum ServiceType {
        PLATFORM,
        SMART_SPACE
    }
}
