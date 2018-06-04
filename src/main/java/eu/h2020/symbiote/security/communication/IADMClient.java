package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.communication.payloads.FailFederationAuthorizationReport;

/**
 * Crude RMI-like client's interface to the AAM module.
 *
 * @author Dariusz Krajewski (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
public interface IADMClient {

    /**
     * @param report report to be sent
     * @return true if anomaly saved
     */
    boolean reportFailedFederatedAuthorization(FailFederationAuthorizationReport report) throws ADMException;
}
