package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.enums.OperationType;

import java.util.HashMap;
import java.util.Map;

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
    private UserDetails userDetails = new UserDetails();
    private Map<String, String> userAttributes = new HashMap<>();
    private OperationType operationType;

    /**
     * used by JSON serializer
     */
    public UserManagementRequest() { // used by JSON serializer
    }

    public UserManagementRequest(Credentials administratorCredentials, Credentials userCredentials,
                                 UserDetails userDetails, Map<String, String> userAttributes, OperationType operationType) {
        this.administratorCredentials = administratorCredentials;
        this.userCredentials = userCredentials;
        this.userDetails = userDetails;
        this.operationType = operationType;
        this.userAttributes = userAttributes;
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

    public Map<String, String> getUserAttributes() {
        return userAttributes;
    }

    public void setUserAttributes(Map<String, String> userAttributes) {
        this.userAttributes = userAttributes;
    }

}
