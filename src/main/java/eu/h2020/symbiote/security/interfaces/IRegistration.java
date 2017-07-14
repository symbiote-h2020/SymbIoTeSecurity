package eu.h2020.symbiote.security.interfaces;

import eu.h2020.symbiote.security.constants.SecurityConstants;
import eu.h2020.symbiote.security.payloads.UserManagementRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * TODO R3 do we even need rest api if we have an AMQP interface for that?
 * Access to other services offered by ApplicationRegistrationController.
 *
 * @author Piotr Kicki (PSNC)
 */
public interface IRegistration {


    @PostMapping(value = SecurityConstants.AAM_PUBLIC_PATH + "/register")
    ResponseEntity<?> register(@RequestBody UserManagementRequest request);

    @PostMapping(value = SecurityConstants.AAM_PUBLIC_PATH + "/unregister")
    ResponseEntity<?> unregister(@RequestBody UserManagementRequest request);
}
