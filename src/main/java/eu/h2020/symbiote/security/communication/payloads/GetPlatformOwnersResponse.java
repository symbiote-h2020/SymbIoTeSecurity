package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpStatus;

import java.util.Map;

public class GetPlatformOwnersResponse {
    private final Map<String, String> platformsOwners;
    private final HttpStatus httpStatus;

    @JsonCreator
    public GetPlatformOwnersResponse(@JsonProperty("platformsOwners") Map<String, String> platformsOwners,
                                     @JsonProperty("httpStatus") HttpStatus httpStatus) {
        this.platformsOwners = platformsOwners;
        this.httpStatus = httpStatus;
    }

    public Map<String, String> getplatformsOwners() {
        return platformsOwners;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
