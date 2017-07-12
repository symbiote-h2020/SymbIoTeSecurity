package eu.h2020.symbiote.security.payloads;

/**
 * Describes user registration in AAM payload.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 * @author Maksymilian Marcinowski (PSNC)
 */
public class UserRegistrationRequest {

    private Credentials administratorCredentials = new Credentials();
    private UserDetails userDetails = new UserDetails();

    /**
     * used by JSON serializer
     */
    public UserRegistrationRequest() { // used by JSON serializer
    }

    public UserRegistrationRequest(Credentials administratorCredentials, UserDetails userDetails) {
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
