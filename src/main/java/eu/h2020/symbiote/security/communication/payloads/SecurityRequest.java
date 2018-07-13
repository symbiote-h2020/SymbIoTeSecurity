package eu.h2020.symbiote.security.communication.payloads;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.exceptions.custom.InvalidArgumentsException;

import java.io.IOException;
import java.util.*;

/**
 * Utility class for containing a set of {@link SecurityCredentials} objects and current timestamp used in the
 * challenge-response procedure ({@link eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper}).
 *
 * @author Daniele Caldarola (CNIT)
 * @author Mikołaj Dobski (PSNC)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SecurityRequest {

    private static final ObjectMapper om = new ObjectMapper();
    private final Set<SecurityCredentials> securityCredentials;
    private final long timestamp;
    private final String proprietarySecurityPayload;


    /**
     * Used to generate the security request
     *
     * @param securityCredentials        mandatory for all Symbiote Levels (1 through 4)
     * @param timestamp                  mandatory for all Symbiote Levels (1 through 4)
     * @param proprietarySecurityPayload (optional) designed for L3/L4 (or any other) resources that need a proprietary security payload that can be checked in RAP plugin.
     */
    @JsonCreator
    public SecurityRequest(
            @JsonProperty(value = "securityCredentials", required = true) Set<SecurityCredentials> securityCredentials,
            @JsonProperty(value = "timestamp", required = true) long timestamp,
            @JsonProperty(value = "proprietarySecurityPayload") String proprietarySecurityPayload) {
        this.securityCredentials = securityCredentials;
        this.timestamp = timestamp;
        if (proprietarySecurityPayload != null)
            this.proprietarySecurityPayload = proprietarySecurityPayload;
        else
            this.proprietarySecurityPayload = "";
    }

    /**
     * Used to generate the security request for L1/L2 resources access without support for the proprietary security schema.
     *
     * @param securityCredentials
     * @param timestamp
     */
    public SecurityRequest(
            Set<SecurityCredentials> securityCredentials,
            long timestamp) {
        this(securityCredentials,
                timestamp,
                "");
    }

    /**
     * Used to generate the security request needed to access public resources
     *
     * @param guestToken acquired from whichever symbIoTe AAM
     */
    public SecurityRequest(String guestToken) {
        // JWT rounds to seconds
        long now = new Date().getTime();
        this.timestamp = now - now % 1000;
        this.securityCredentials = new HashSet<>();
        securityCredentials.add(new SecurityCredentials(guestToken));
        this.proprietarySecurityPayload = "";
    }

    /**
     * @param securityRequestHeaderParams containing map of HTTP request headers in which one can find the serialized security headers
     *                                    must contain:
     *                                    {@link SecurityConstants#SECURITY_CREDENTIALS_TIMESTAMP_HEADER} containing the timestamp
     *                                    {@link SecurityConstants#SECURITY_CREDENTIALS_SIZE_HEADER} number of the credentials
     *                                    and a set of 1..n entries prefixed with
     *                                    {@link SecurityConstants#SECURITY_CREDENTIALS_HEADER_PREFIX} containing serialized {@link SecurityCredentials}
     * @throws InvalidArgumentsException or missing headers or malformed values
     */
    public SecurityRequest(Map<String, String> securityRequestHeaderParams) throws InvalidArgumentsException {

        // SecurityConstants.SECURITY_CREDENTIALS_TIMESTAMP_HEADER
        String timestampString = securityRequestHeaderParams.get(SecurityConstants.SECURITY_CREDENTIALS_TIMESTAMP_HEADER);
        if (timestampString == null)
            throw new InvalidArgumentsException("Missing required header: " + SecurityConstants.SECURITY_CREDENTIALS_TIMESTAMP_HEADER);
        if (timestampString.isEmpty())
            throw new InvalidArgumentsException("Header '" + SecurityConstants.SECURITY_CREDENTIALS_TIMESTAMP_HEADER + "' can not be empty.");
        try {
            this.timestamp = Long.parseLong(timestampString);
        } catch (NumberFormatException e) {
            throw new InvalidArgumentsException("Malformed required header: " + SecurityConstants.SECURITY_CREDENTIALS_TIMESTAMP_HEADER);
        }

        // SecurityConstants.SECURITY_CREDENTIALS_SIZE_HEADER parsing
        String credentialsSetSizeString = securityRequestHeaderParams.get(SecurityConstants.SECURITY_CREDENTIALS_SIZE_HEADER);
        if (credentialsSetSizeString == null)
            throw new InvalidArgumentsException("Missing required header: " + SecurityConstants.SECURITY_CREDENTIALS_SIZE_HEADER);
        if (credentialsSetSizeString.isEmpty())
            throw new InvalidArgumentsException("Header  '" + SecurityConstants.SECURITY_CREDENTIALS_SIZE_HEADER + "' can not be empty.");
        int credentialsSetSize;
        try {
            credentialsSetSize = Integer.parseInt(credentialsSetSizeString);
        } catch (NumberFormatException e) {
            throw new InvalidArgumentsException("Malformed required header: " + SecurityConstants.SECURITY_CREDENTIALS_SIZE_HEADER);
        }

        //SecurityConstrants.PROPRIETARY_SECURITY_PAYLOAD parsing
        this.proprietarySecurityPayload = securityRequestHeaderParams.getOrDefault(SecurityConstants.PROPRIETARY_SECURITY_PAYLOAD,"");

        // deserializing SecurityCredentials Set
        this.securityCredentials = new HashSet<>();
        for (int i = 1; i <= credentialsSetSize; i++) {
            String securityCredentialsString = securityRequestHeaderParams.get(SecurityConstants.SECURITY_CREDENTIALS_HEADER_PREFIX + i);
            if (securityCredentialsString == null)
                throw new InvalidArgumentsException("Missing/malformed required header: " + SecurityConstants.SECURITY_CREDENTIALS_HEADER_PREFIX + i);
            if (securityCredentialsString.isEmpty())
                throw new InvalidArgumentsException("Header '" + SecurityConstants.SECURITY_CREDENTIALS_HEADER_PREFIX + i + "' can not be empty.");
            try {
                this.securityCredentials.add(om.readValue(securityCredentialsString, SecurityCredentials.class));
            } catch (IOException e) {
                throw new InvalidArgumentsException("Missing/malformed required header: " + SecurityConstants.SECURITY_CREDENTIALS_HEADER_PREFIX + i + " " + e.getMessage());
            }
        }
    }

    public Set<SecurityCredentials> getSecurityCredentials() {
        return securityCredentials;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String getProprietarySecurityPayload() {
        return proprietarySecurityPayload;
    }

    /**
     * @return HTTP headers containing entries required to rebuild the Security Request on the server side
     * @throws JsonProcessingException on @{@link SecurityCredentials} serialization error
     */
    @JsonIgnore
    public Map<String, String> getSecurityRequestHeaderParams() throws JsonProcessingException {
        Map<String, String> securityHeaderParams = new HashMap<>();
        securityHeaderParams.put(SecurityConstants.SECURITY_CREDENTIALS_TIMESTAMP_HEADER, String.valueOf(timestamp));
        securityHeaderParams.put(SecurityConstants.SECURITY_CREDENTIALS_SIZE_HEADER, String.valueOf(securityCredentials.size()));
        int headerNumber = 1;
        for (SecurityCredentials securityCredential : securityCredentials) {
            securityHeaderParams.put(SecurityConstants.SECURITY_CREDENTIALS_HEADER_PREFIX + headerNumber, om.writeValueAsString(securityCredential));
            headerNumber++;
        }
        if (!proprietarySecurityPayload.isEmpty())
            securityHeaderParams.put(SecurityConstants.PROPRIETARY_SECURITY_PAYLOAD, proprietarySecurityPayload);

        return securityHeaderParams;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityRequest that = (SecurityRequest) o;
        return timestamp == that.timestamp &&
                Objects.equals(securityCredentials, that.securityCredentials) &&
                Objects.equals(proprietarySecurityPayload, that.proprietarySecurityPayload);
    }

    @Override
    public int hashCode() {

        return Objects.hash(securityCredentials, timestamp, proprietarySecurityPayload);
    }

}
