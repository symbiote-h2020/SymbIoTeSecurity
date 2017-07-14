package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.SecurityConstants;
import eu.h2020.symbiote.security.payloads.Credentials;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

/**
 * Exposes services allowing SymbIoTe actors (users) to acquire authorization tokens
 * <p>
 * TODO @Jakub rework to return Token Strings or something like that
 *
 * @author Piotr Kicki (PSNC)
 */
public interface IGetToken {
    /**
     * @return GUEST token used to access public resources offered in SymbIoTe
     */
    @PostMapping(value = SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_GUEST_TOKEN)
    ResponseEntity<?> getGuestToken();

    /**
     * @param user TODO rework for signed login request
     * @return HOME token used to access restricted resources offered in SymbIoTe
     */
    @PostMapping(value = SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_HOME_TOKEN)
    ResponseEntity<?> getHomeToken(@RequestBody Credentials user);

    /**
     * @param homeToken that an actor wants to exchange in this AAM for a FOREIGN token
     * @return FOREIGN token used to access restricted resources offered in SymbIoTe federations
     */
    @PostMapping(value = SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_FOREIGN_TOKEN)
    ResponseEntity<?> getForeignToken(@RequestHeader(SecurityConstants.TOKEN_HEADER_NAME)
                                              String homeToken);
}
