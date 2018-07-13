package eu.h2020.symbiote.security.commons;

/**
 * Class containing all of the available components identifiers used during mutual authentication
 * @author Jakub Toczek (PSNC)
 * @author Mikołaj Dobski (PSNC)
 */
public class ComponentIdentifiers {
    public static final String CORE_REGISTRY = "registry";
    public static final String CORE_SEARCH = "search";
    public static final String CORE_RESOURCE_ACCESS_MONITOR = "cram";
    public static final String CORE_RESOURCE_MONITOR = "crm";
    public static final String CORE_ANOMALY_DETECTION = "adm";
    public static final String RESOURCE_ACCESS_PROXY = "rap";
    public static final String REGISTRATION_HANDLER = "reghandler";
    public static final String PLATFORM_MONITORING = "monitoring";
    public static final String ENABLER_RESOURCE_MANAGER = "erm";
    public static final String ENABLER_PLATFORM_PROXY = "epp";
    public static final String ADMINISTRATION = "administration";
    public static final String FEDERATION_MANAGER = "fm";
    public static final String SUBSCRIPTION_MANAGER = "subscriptionManager";
    public static final String PLATFORM_REGISTRY = "platformRegistry";
    private ComponentIdentifiers() {
    }
}
