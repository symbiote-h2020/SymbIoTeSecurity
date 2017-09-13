package eu.h2020.symbiote.security.communication;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;
import feign.Client;
import feign.Request;
import feign.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

public class SymbioteAuthorizationClient implements Client {
  
  private static final Log logger = LogFactory.getLog(SymbioteAuthorizationClient.class);
  
  private IComponentSecurityHandler handler = null;
  private Client client;
  private String serviceComponentIdentifier;
  private String servicePlatformIdentifier;

    /**
     *
     * @param handler configured for this component
     * @param serviceComponentIdentifier of the service this client is used to communicate with
     * @param servicePlatformIdentifier  to which the service belongs ({@link SecurityConstants#CORE_AAM_INSTANCE_ID} for Symbiote core components)
     * @param client used for business logic
     */
  public SymbioteAuthorizationClient(IComponentSecurityHandler handler, String serviceComponentIdentifier, String servicePlatformIdentifier, Client client) {
    this.handler = handler;
    this.serviceComponentIdentifier = serviceComponentIdentifier;
    this.servicePlatformIdentifier = servicePlatformIdentifier;
    this.client = client;
  }
  
  
  @Override
  public Response execute(Request request, Request.Options options) throws IOException {
    
    try {
      SecurityRequest credentials = handler.generateSecurityRequestUsingCoreCredentials();
      request.headers().putAll(credentials.getSecurityRequestHeaderParams().entrySet().stream()
                                   .collect(Collectors.toMap(entry -> entry.getKey(),
                                       entry -> Arrays.asList(entry.getValue()))));
    
      Response response = client.execute(request, options);
    
      if (response.status() >= 200 && response.status() < 300) {
        Collection<String> secResponse =
            response.headers().get(SecurityConstants.SECURITY_RESPONSE_HEADER);
      
        if (secResponse != null && !secResponse.isEmpty()) {
            if (!handler.isReceivedServiceResponseVerified(secResponse.iterator().next(), serviceComponentIdentifier, servicePlatformIdentifier)) {
                return Response.builder().status(400).reason("Server response verification failed").build();
          }
        } else {
          return Response.builder().status(400).reason("Missing server challenge response").build();
        }
      }
    
      return response;
    
    } catch (SecurityHandlerException e) {
      logger.error("Can't get authorization credentials", e);
    } catch (JsonProcessingException e) {
      logger.error("Error getting authorization headers from request");
    }
  
    return Response.builder().status(401).reason("Can't get authorization credentials").build();
  }
}