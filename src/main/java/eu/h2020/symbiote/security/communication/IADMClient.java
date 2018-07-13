package eu.h2020.symbiote.security.communication;

import eu.h2020.symbiote.security.commons.exceptions.custom.ADMException;
import eu.h2020.symbiote.security.communication.payloads.FailedFederationAuthorizationReport;

/**
 * Crude RMI-like client's interface to the Anomaly Detection Module.
 *
 * @author Jakub Toczek (PSNC)
 * @author Mikolaj Dobski (PSNC)
 */
public interface IADMClient {

    /**
     * @param report report to be sent
     * @return true if reported anomaly was saved
     */
    boolean reportFailedFederatedAuthorization(FailedFederationAuthorizationReport report) throws ADMException;
}
