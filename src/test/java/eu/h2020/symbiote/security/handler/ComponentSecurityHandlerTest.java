package eu.h2020.symbiote.security.handler;

import eu.h2020.symbiote.security.ComponentSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import org.junit.After;
import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;

import java.io.File;

/**
 * @author Mikołaj Dobski (PSNC)
 */

public class ComponentSecurityHandlerTest {

    private final String badComponentId = "component.1";
    private final String badPlatformId = "plat.formid";
    private final String goodComponentId = "Component-id_1";
    private final String goodPlatformId = "Platform-id_1";

    @Test(expected = SecurityHandlerException.class)
    public void badComponentIdTest() throws SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                badComponentId + "@" + goodPlatformId,
                "irrelevant",
                false,
                "irrelevant",
                "irrelevant"
        );
    }


    @Test(expected = SecurityHandlerException.class)
    public void badPlatformIdTest() throws SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                goodComponentId + "@" + badPlatformId,
                "irrelevant",
                false,
                "irrelevant",
                "irrelevant"
        );
    }

    @Test(expected = SecurityHandlerException.class)
    public void missingPartOfTheIdTest() throws SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                goodComponentId,
                "irrelevant",
                false,
                "irrelevant",
                "irrelevant"
        );
    }

    @Test(expected = SecurityHandlerException.class)
    public void TooManyParts() throws SecurityHandlerException {
        ComponentSecurityHandlerFactory.getComponentSecurityHandler(
                "irrelevant",
                "irrelevant",
                goodComponentId + "@" + goodPlatformId + "@" + goodPlatformId,
                "irrelevant",
                false,
                "irrelevant",
                "irrelevant"
        );
    }

    @Test(expected = SecurityHandlerException.class)
    public void noConnectionComponentIdTest() throws SecurityHandlerException {

        ISecurityHandler mock = PowerMockito.mock(ISecurityHandler.class);

        ComponentSecurityHandler componentSecurityHandler = new ComponentSecurityHandler(
                mock,
                "irrelevant",
                false,
                "irrelevant",
                "irrelevant",
                goodComponentId + "@" + goodPlatformId);
    }

    @After
    public void deleteKeystore() {
        File file = new File("irrelevant");
        file.delete();
    }

}