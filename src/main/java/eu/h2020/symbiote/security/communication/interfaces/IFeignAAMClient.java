package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.payloads.*;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;

/**
 * Access to services provided by AAMS
 *
 * @author Dariusz Krajewski (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public interface IFeignAAMClient {

    @RequestLine("GET " + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
    @Headers("Content-Type: application/json")
    AvailableAAMsCollection getAvailableAAMs();

    @RequestLine("GET " + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    Response getComponentCertificate();

    @RequestLine("POST " + SecurityConstants.AAM_GET_CLIENT_CERTIFICATE)
    @Headers("Content-Type: application/json")
    Response getClientCertificate(CertificateRequest certificateRequest);

    @RequestLine("POST " + SecurityConstants.AAM_REVOKE)
    @Headers("Content-Type: application/json")
    Response revoke(RevocationRequest revocationRequest);

    @RequestLine("POST " + SecurityConstants.AAM_GET_GUEST_TOKEN)
    Response getGuestToken();

    @RequestLine("POST " + SecurityConstants.AAM_GET_HOME_TOKEN)
    @Headers({"Content-Type: text/plain", "Accept: text/plain",
            SecurityConstants.TOKEN_HEADER_NAME + ": " + "{token}"})
    Response getHomeToken(@Param("token") String loginRequest);

    @RequestLine("POST " + SecurityConstants.AAM_GET_FOREIGN_TOKEN)
    @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}",
            SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME + ": {clientCertificate}",
            SecurityConstants.AAM_CERTIFICATE_HEADER_NAME + ": {aamCertificate}",
            "Accept: application/json"})
    Response getForeignToken(@Param("token") String homeToken,
                             @Param("clientCertificate") String clientCertificate,
                             @Param("aamCertificate") String aamCertificate);

    @RequestLine("POST " + SecurityConstants.AAM_VALIDATE)
    @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}",
            SecurityConstants.CLIENT_CERTIFICATE_HEADER_NAME + ": {clientCertificate}",
            SecurityConstants.AAM_CERTIFICATE_HEADER_NAME + ": {clientCertificateSigningAAMCertificate}",
            SecurityConstants.FOREIGN_TOKEN_ISSUING_AAM_CERTIFICATE + ": {foreignTokenIssuingAAMCertificate}",
            "Accept: application/json"})
    ValidationStatus validate(@Param("token") String token,
                              @Param("clientCertificate") String clientCertificate,
                              @Param("clientCertificateSigningAAMCertificate") String clientCertificateSigningAAMCertificate,
                              @Param("foreignTokenIssuingAAMCertificate") String foreignTokenIssuingAAMCertificate);

    @RequestLine("POST " + SecurityConstants.AAM_MANAGE_PLATFORMS)
    @Headers("Content-Type: application/json")
    PlatformManagementResponse manage(PlatformManagementRequest platformManagementRequest);

    @RequestLine("POST " + SecurityConstants.AAM_MANAGE_USERS)
    @Headers("Content-Type: application/json")
    ManagementStatus manage(UserManagementRequest userManagementRequest);

    @RequestLine("POST " + "/getUserDetails")
    @Headers("Content-Type: application/json")
    UserDetails getUserDetails(Credentials credentials);
}