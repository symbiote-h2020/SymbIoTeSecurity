package eu.h2020.symbiote.security.clients;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.enums.ValidationStatus;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import eu.h2020.symbiote.security.communication.interfaces.payloads.CertificateRequest;
import eu.h2020.symbiote.security.communication.interfaces.payloads.Credentials;

import feign.Headers;
import feign.Param;
import feign.RequestLine;

import java.util.Map;

public interface AAMClient {
  
  @RequestLine("GET "+ SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS)
  Map<String, AAM> getAvailableAAMs();
  
  @RequestLine("POST "+ SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_CLIENT_CERTIFICATE)
  String getClientCertificate(CertificateRequest certificateRequest);
  
  @RequestLine("GET "+ SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_COMPONENT_CERTIFICATE)
  String getComponentCertificate();
  
  @RequestLine("POST "+ SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_GUEST_TOKEN)
  Token getGuestToken();
  
  @RequestLine("POST "+ SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_HOME_TOKEN)
  Token getHomeToken(Credentials user);
  
  @RequestLine("POST "+ SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_FOREIGN_TOKEN)
  @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}"})
  Token getForeignToken(@Param("token") String homeToken);
  
  @RequestLine("POST "+ SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_VALIDATE)
  @Headers({SecurityConstants.TOKEN_HEADER_NAME + ": {token}",
               SecurityConstants.CERTIFICATE_HEADER_NAME + ": {certificate}"} )
  ValidationStatus validate(@Param("token") String token,
                            @Param("certificate") String certificate);
}
