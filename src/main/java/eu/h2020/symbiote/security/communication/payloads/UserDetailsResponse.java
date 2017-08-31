package eu.h2020.symbiote.security.communication.payloads;

import org.springframework.http.HttpStatus;

public class UserDetailsResponse {
    private HttpStatus httpStatus;
    private UserDetails userDetails;

    public UserDetailsResponse(HttpStatus httpStatus, UserDetails userDetails) {
        this.httpStatus = httpStatus;
        this.userDetails = userDetails;
    }

    public UserDetailsResponse() {

    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }

    public void setUserDetails(UserDetails userDetails) {
        this.userDetails = userDetails;
    }
}
