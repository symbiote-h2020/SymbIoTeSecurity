package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public class GetPlatformOwnersRequest {
    private final Credentials administratorCredentials;
    private final Set<String> platformsIdentifiers;

    @JsonCreator
    public GetPlatformOwnersRequest(@JsonProperty("administratorCredentials") Credentials administratorCredentials,
                                    @JsonProperty("platformsIdentifiers") Set<String> platformsIdentifiers) {
        this.platformsIdentifiers = platformsIdentifiers;
        this.administratorCredentials = administratorCredentials;
    }

    public Credentials getAdministratorCredentials() {
        return administratorCredentials;
    }

    public Set<String> getPlatformsIdentifiers() {
        return platformsIdentifiers;
    }
}
