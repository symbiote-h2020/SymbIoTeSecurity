package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpStatus;

public class UserDetailsResponse {
    private final HttpStatus httpStatus;
    private final UserDetails userDetails;

    @JsonCreator
    public UserDetailsResponse(@JsonProperty("httpStatus") HttpStatus httpStatus, @JsonProperty("userDetails") UserDetails userDetails) {
        this.httpStatus = httpStatus;
        this.userDetails = userDetails;
    }


    public HttpStatus getHttpStatus() {
        return httpStatus;
    }


    public UserDetails getUserDetails() {
        return userDetails;
    }

}
