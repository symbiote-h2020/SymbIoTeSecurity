package eu.h2020.symbiote.security.communication.payloads;

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
    private UserDetails userDetails = new UserDetails();

    /**
     * used by JSON serializer
     */
    public UserManagementRequest() { // used by JSON serializer
    }

    public UserManagementRequest(Credentials administratorCredentials, UserDetails userDetails) {
        this.administratorCredentials = administratorCredentials;
        this.userDetails = userDetails;
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
}
