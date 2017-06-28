package eu.h2020.symbiote.security.rest;

import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.payloads.CheckRevocationResponse;
import eu.h2020.symbiote.security.payloads.Credentials;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;

/**
 * Contains services exposed by all AAMs in Symbiote.
 */
public interface AAMRESTInterface {
    @RequestLine("GET " + AAMConstants.AAM_GET_CA_CERTIFICATE)
    @Headers("Accept: multipart/form-data")
    String getRootCertificate();

    @RequestLine("POST " + AAMConstants.AAM_LOGIN)
    @Headers("Content-Type: application/json")
    Response login(Credentials credential);

    @RequestLine("POST " + AAMConstants.AAM_VALIDATE)
    @Headers({"Content-Type: application/json", "Accept: application/json", AAMConstants.TOKEN_HEADER_NAME + ": " +
            "{token}"})
    CheckRevocationResponse validate(@Param("token") String token);

    @RequestLine("POST " + AAMConstants.AAM_REQUEST_FOREIGN_TOKEN)
    @Headers({"Content-Type: application/json", "Accept: application/json", AAMConstants.TOKEN_HEADER_NAME + ": " +
            "{token}"})
    Response requestForeignToken(@Param("token") String token);
}