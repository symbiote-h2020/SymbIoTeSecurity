package eu.h2020.symbiote.security.clients;

import feign.Feign;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;

public class ClientFactory {
  
  public static AAMClient getAAMClient(String baseUrl) {
    
    return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
        .target(AAMClient.class, baseUrl);
    
  }
  
}
