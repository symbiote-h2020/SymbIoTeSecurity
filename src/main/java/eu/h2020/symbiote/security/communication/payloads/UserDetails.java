package eu.h2020.symbiote.security.communication.payloads;

import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.UserRole;

import java.util.HashMap;
import java.util.Map;

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
    private Map<String, String> attributes = new HashMap<>();
    private Map<String, Certificate> clients = new HashMap<>();

    public UserDetails() {
        // used in serialization and in UserManagementRequest
    }

    /**
     * UserDetails constructor
     *
     * @param userCredentials Credentials identifying user
     * @param federatedId     federatedID
     * @param recoveryMail    Recovery mail of the user
     * @param role            Role of the user (USER, PLATFORM_OWNER, NULL)
     * @param attributes      This user attributes. NOTE: during update, in case of empty map, attributes also will be updated (removed)
     * @param clients         user's clients
     */
    public UserDetails(Credentials userCredentials,
                       String federatedId,
                       String recoveryMail,
                       UserRole role,
                       Map<String, String> attributes,
                       Map<String, Certificate> clients) {
        this.userCredentials = userCredentials;
        this.federatedId = federatedId;
        this.recoveryMail = recoveryMail;
        this.role = role;
        this.attributes = attributes;
        this.clients = clients;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes = attributes;
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
