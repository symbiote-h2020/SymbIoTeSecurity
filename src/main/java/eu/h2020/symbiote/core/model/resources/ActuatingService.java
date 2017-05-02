package eu.h2020.symbiote.core.model.resources;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.h2020.symbiote.core.model.Property;

import java.util.List;

/**
 * Represents CIM-defined Actuating Service class.
 *
 * Created by Mael on 28/03/2017.
 */
public class ActuatingService extends Service {

    @JsonProperty("actsOn")
    private String actsOn;
    @JsonProperty("affects")
    private List<String> affects;

    public ActuatingService() {
    }

    public String getActsOn() {
        return actsOn;
    }

    public void setActsOn(String actsOn) {
        this.actsOn = actsOn;
    }

    public List<String> getAffects() {
        return affects;
    }

    public void setAffects(List<String> affects) {
        this.affects = affects;
    }
}