package eu.h2020.symbiote.core.model.resources;

import com.fasterxml.jackson.annotation.JsonProperty;

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
    private String locatedAt;

    @JsonProperty("capabilites")
    private List<String> capabilities;

    public Actuator() {
    }

    public String getLocatedAt() {
        return locatedAt;
    }

    public void setLocatedAt(String locatedAt) {
        this.locatedAt = locatedAt;
    }

    public List<String> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(List<String> capabilities) {
        this.capabilities = capabilities;
    }
}