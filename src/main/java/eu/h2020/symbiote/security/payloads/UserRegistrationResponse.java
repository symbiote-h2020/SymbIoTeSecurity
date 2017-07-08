package eu.h2020.symbiote.security.payloads;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.enums.RegistrationStatus;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Class that defines the structure of a user registration response sent by AAM.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikołaj Dobski (PSNC)
 */
public class UserRegistrationResponse {

    private static Log log = LogFactory.getLog(UserRegistrationResponse.class);

    // TODO Release 3 fix to support CertificateSignRequests
    private RegistrationStatus registrationStatus;

    /**
     * required for JSON serialization
     */
    public UserRegistrationResponse() {
        // required by JSON
    }

    public UserRegistrationResponse(RegistrationStatus registrationStatus) {
        this.registrationStatus = registrationStatus;
    }

    public RegistrationStatus getRegistrationStatus() {
        return registrationStatus;
    }

    public void setRegistrationStatus(RegistrationStatus registrationStatus) {
        this.registrationStatus = registrationStatus;
    }

    public String toJson() {
        ObjectMapper om = new ObjectMapper();
        try {
            return om.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            log.error("Error converting UserRegistrationResponse to JSON", e);
            return null;
        }
    }


}
