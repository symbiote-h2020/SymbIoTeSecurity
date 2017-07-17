package eu.h2020.symbiote.security.communication.interfaces;

import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.communication.interfaces.payloads.AAM;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

/**
 * Access to other services that AAMs offer.
 *
 * @author Mikołaj Dobski (PSNC)
 */
public interface IAAMServices {

    /**
     * @return collection of AAMs available in the SymbIoTe ecosystem
     */
    @GetMapping(value = SecurityConstants.AAM_PUBLIC_PATH + SecurityConstants.AAM_GET_AVAILABLE_AAMS, produces =
            "application/json")
    Map<String, AAM> getAvailableAAMs();
}
