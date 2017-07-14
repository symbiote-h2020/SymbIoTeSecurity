package eu.h2020.symbiote.security.payloads;

import eu.h2020.symbiote.security.enums.UserRole;

/**
 * Contains Symbiote User JSON details
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class UserDetails {

    private Credentials userCredentials = new Credentials();
    private String recoveryMail = "";
    private UserRole role = UserRole.NULL;
    // TODO review for R4
    private String federatedId = "";

    // TODO add user's clients certificates

    public UserDetails() {
        // used in serialization
    }

    public UserDetails(Credentials userCredentials, String federatedId, String recoveryMail, UserRole role) {
        this.userCredentials = userCredentials;
        this.federatedId = federatedId;
        this.recoveryMail = recoveryMail;
        this.role = role;
    }

    public Credentials getCredentials() {
        return userCredentials;
    }

    public void setCredentials(Credentials userCredentials) {
        this.userCredentials = userCredentials;
    }

    public String getFederatedId() {
        return federatedId;
    }

    public void setFederatedID(String federatedId) {
        this.federatedId = federatedId;
    }

    public String getRecoveryMail() {
        return recoveryMail;
    }

    public void setRecoveryMail(String recoveryMail) {
        this.recoveryMail = recoveryMail;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }
}
