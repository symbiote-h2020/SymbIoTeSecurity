package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.enums.OperationType;

/**
 * Describes user registration in AAM payload.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class UserManagementRequest {

    private Credentials administratorCredentials = new Credentials();
    private Credentials userCredentials = new Credentials();
    private UserDetails userDetails;
    private OperationType operationType;

    /**
     * used by JSON serializer
     */
    public UserManagementRequest() { // used by JSON serializer
    }

    @JsonCreator
    public UserManagementRequest(
            @JsonProperty("administratorCredentials") Credentials administratorCredentials,
            @JsonProperty("userCredentials") Credentials userCredentials,
            @JsonProperty("userDetails") UserDetails userDetails,
            @JsonProperty("operationType") OperationType operationType) {
        this.administratorCredentials = administratorCredentials;
        this.userCredentials = userCredentials;
        this.userDetails = userDetails;
        this.operationType = operationType;
    }

    public Credentials getAdministratorCredentials() {
        return administratorCredentials;
    }

    public void setAdministratorCredentials(Credentials administratorCredentials) {
        this.administratorCredentials = administratorCredentials;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }

    public void setUserDetails(UserDetails userDetails) {
        this.userDetails = userDetails;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public void setOperationType(OperationType operationType) {
        this.operationType = operationType;
    }

    public Credentials getUserCredentials() {
        return userCredentials;
    }

    public void setUserCredentials(Credentials userCredentials) {
        this.userCredentials = userCredentials;
    }

}
