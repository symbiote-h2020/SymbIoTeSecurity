package eu.h2020.symbiote.core.model.resources;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.core.model.Location;

import java.util.List;

/**
 * Represents CIM-defined Actuator class. Actuator specifies location it is located at (using unique location identifier
 * defined by platform the actuator belongs to) as well as a list of actuating services it is using (by specifying list
 * of symbIoTe Ids of the services).
 *
 * Created by Mael on 28/03/2017.
 */
public class Actuator extends Resource {

    @JsonProperty("locatedAt")
    private Location locatedAt;

    @JsonProperty("capabilites")
    private List<ActuatingService> capabilities;

    public Actuator() {
    }

    public Location getLocatedAt() {
        return locatedAt;
    }

    public void setLocatedAt(Location locatedAt) {
        this.locatedAt = locatedAt;
    }

    public List<ActuatingService> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(List<ActuatingService> capabilities) {
        this.capabilities = capabilities;
    }
}
