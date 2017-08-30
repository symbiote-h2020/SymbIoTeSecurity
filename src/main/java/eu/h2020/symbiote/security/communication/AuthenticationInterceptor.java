package eu.h2020.symbiote.security.communication;

import com.fasterxml.jackson.core.JsonProcessingException;

import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.IComponentSecurityHandler;

import feign.RequestInterceptor;
import feign.RequestTemplate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;
import java.util.stream.Collectors;

public class AuthenticationInterceptor implements RequestInterceptor {
  
  private static final Log logger = LogFactory.getLog(AuthenticationInterceptor.class);
  
  private IComponentSecurityHandler handler = null;
  
  public AuthenticationInterceptor(IComponentSecurityHandler handler) {
    this.handler = handler;
  }
  
  @Override
  public void apply(RequestTemplate template) {
    try {
      SecurityRequest credentials = handler.generateSecurityRequestUsingCoreCredentials();
      template.headers(credentials.getSecurityRequestHeaderParams().entrySet().stream()
                           .collect(Collectors.toMap(entry -> entry.getKey(),
                               entry -> Arrays.asList(entry.getValue()))));
    } catch (SecurityHandlerException e) {
      logger.error("Can't get authorization credentials", e);
    } catch (JsonProcessingException e) {
      logger.error("Error getting authorization headers from request");
    }
  }
}
