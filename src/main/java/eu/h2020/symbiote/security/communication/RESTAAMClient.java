package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.communication.interfaces.FeignAAMRESTInterface;
import feign.Feign;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;

/**
 * For easier response handling (WIP)
 *
 * @author Dariusz Krajewski (PSNC)
 */
public class RESTAAMClient {

    public static FeignAAMRESTInterface getJsonClient(String serveraddress) {
        return Feign.builder().encoder(new JacksonEncoder()).decoder(new JacksonDecoder())
                .target(FeignAAMRESTInterface.class, serveraddress);
    }
}
