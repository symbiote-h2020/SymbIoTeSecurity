package eu.h2020.symbiote.security.listeners.rest;

import eu.h2020.symbiote.security.constants.SecurityConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.payloads.Credentials;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.Response;

/**
 * Contains services exposed by all AAMs in Symbiote.
 * TODO R3 just extend the particular AAMinterfaces!!!
 */
public interface AAMRESTInterface {
    @RequestLine("GET " + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
    @Headers("Accept: multipart/form-data")
    String getRootCertificate();

    @RequestLine("POST " + SecurityConstants.AAM_GET_HOME_TOKEN)
    @Headers("Content-Type: application/json")
    Response login(Credentials credential);

    @RequestLine("POST " + SecurityConstants.AAM_VALIDATE)
    @Headers({"Content-Type: application/json", "Accept: application/json", SecurityConstants.TOKEN_HEADER_NAME + ": " +
            "{token}"})
    ValidationStatus validate(@Param("token") String token);

    @RequestLine("POST " + SecurityConstants.AAM_GET_FOREIGN_TOKEN)
    @Headers({"Content-Type: application/json", "Accept: application/json", SecurityConstants.TOKEN_HEADER_NAME + ": " +
            "{token}"})
    Response requestForeignToken(@Param("token") String token);
}