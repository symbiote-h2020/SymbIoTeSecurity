package eu.h2020.symbiote.security.clients;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.payloads.AvailableAAMsCollection;
import eu.h2020.symbiote.security.communication.payloads.CertificateRequest;
import feign.Headers;
import feign.Param;
import feign.RequestLine;

/**
 * Use @{@link eu.h2020.symbiote.security.communication.interfaces.FeignAAMRESTInterface} instead of this one.
 */
@Deprecated
public interface AAMClient {

    @RequestLine("GET "+ SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    @Headers({"Accept: application/json"})
    AvailableAAMsCollection getAvailableAAMs();

    @RequestLine("POST "+ SecurityConstants.AAM_GET_CLIENT_CERTIFICATE)
    @Headers({"Accept: application/json", "Content-Type: application/json"})
    String getClientCertificate(CertificateRequest certificateRequest);

    @RequestLine("GET "+ SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    @Headers({"Accept: application/json"})
    String getComponentCertificate();

    @RequestLine("POST "+ SecurityConstants.AAM_GET_GUEST_TOKEN)
    @Headers({"Accept: application/json"})
    String getGuestToken();

    @RequestLine("POST "+ SecurityConstants.AAM_GET_HOME_TOKEN)
    @Headers({"Accept: application/json", "Content-Type: application/json"})
    String getHomeToken(String loginRequest);

    @RequestLine("POST "+ SecurityConstants.AAM_GET_FOREIGN_TOKEN)
    @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}",
            SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME + ": {certificate}",
            "Accept: application/json"})
    String getForeignToken(@Param("token") String homeToken,
                           @Param("certificate") String certificate);

    @RequestLine("POST "+ SecurityConstants.AAM_VALIDATE)
    @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}",
            SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME + ": {certificate}",
            "Accept: application/json"})
    ValidationStatus validate(@Param("token") String token,
                              @Param("certificate") String certificate);
}
