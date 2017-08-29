package eu.h2020.symbiote.security.clients;

import eu.h2020.symbiote.security.communication.AAMClient;

/**
 * Factory class to allow easy testing
 */
public class ClientFactory {

    public static AAMClient getAAMClient(String baseUrl) {
        return new AAMClient(baseUrl);
    }

}
