package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.enums.AccountStatus;
import eu.h2020.symbiote.security.commons.enums.UserRole;

import java.util.HashMap;
import java.util.Map;

/**
 * Contains Symbiote User JSON details
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class UserDetails {
    // TODO R5 harden

    private Credentials userCredentials = new Credentials();
    private String recoveryMail = "";
    private UserRole role = UserRole.NULL;
    private AccountStatus status = AccountStatus.NEW;
    private Map<String, String> attributes = new HashMap<>();
    private Map<String, Certificate> clients = new HashMap<>();

    //GDPR Section
    /**
     * service terms consent is mandatory to provide the service (including suspicious actions identification and blocking)
     */
    private boolean serviceConsent = false;

    /**
     * defines if the user personal data (username, e-mail) and actions can be used for marketing purposes.
     */
    private boolean marketingConsent = false;

    public UserDetails() {
        // used in serialization and in UserManagementRequest
    }

    /**
     * UserDetails constructor
     *
     * @param userCredentials  Credentials identifying user
     * @param recoveryMail     Recovery mail of the user
     * @param role             Role of the user (USER, SERVICE_OWNER, NULL)
     * @param status           Current status of this account
     * @param attributes       This user attributes. NOTE: during update, in case of empty map, attributes also will be updated (removed)
     * @param clients          user's clients
     * @param serviceConsent   service terms consent is mandatory to provide the service (including suspicious actions identification and blocking)
     * @param marketingConsent defines if the user personal data (username, e-mail) and actions can be used for marketing purposes.
     */
    @JsonCreator
    public UserDetails(@JsonProperty("userCredentials") Credentials userCredentials,
                       @JsonProperty("recoveryMail") String recoveryMail,
                       @JsonProperty("role") UserRole role,
                       @JsonProperty("status") AccountStatus status,
                       @JsonProperty("attributes") Map<String, String> attributes,
                       @JsonProperty("clients") Map<String, Certificate> clients,
                       @JsonProperty("serviceConsent") boolean serviceConsent,
                       @JsonProperty("marketingConsent") boolean marketingConsent) {
        this.userCredentials = userCredentials;
        this.recoveryMail = recoveryMail;
        this.role = role;
        this.status = status;
        this.attributes = attributes;
        this.clients = clients;
        this.serviceConsent = serviceConsent;
        this.marketingConsent = marketingConsent;
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

    public Map<String, Certificate> getClients() {
        return clients;
    }

    public AccountStatus getStatus() {
        return status;
    }

    public void setStatus(AccountStatus status) {
        this.status = status;
    }

    @JsonGetter("serviceConsent")
    public boolean hasGrantedServiceConsent() {
        return serviceConsent;
    }

    public void setServiceConsent(boolean serviceConsent) {
        this.serviceConsent = serviceConsent;
    }

    @JsonGetter("marketingConsent")
    public boolean hasGrantedMarketingConsent() {
        return marketingConsent;
    }

    public void setMarketingConsent(boolean marketingConsent) {
        this.marketingConsent = marketingConsent;
    }
}
