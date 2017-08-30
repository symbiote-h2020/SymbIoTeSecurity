package eu.h2020.symbiote.security.commons;

/**
 * Constants related to SH-AAM communication
 * <p>
 * TODO R3 review to remove obsolete values
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Nemanja Ignjatov (UNIVIE)
 */
public class SecurityConstants {
    public static final long serialVersionUID = 7526472295622776147L;

    // Security GLOBAL
    public static final String CURVE_NAME = "secp256r1";
    public static final String KEY_PAIR_GEN_ALGORITHM = "ECDSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    // AAM GLOBAL
    public static final String AAM_CORE_AAM_FRIENDLY_NAME = "SymbIoTe Core AAM";
    public static final String AAM_CORE_AAM_INSTANCE_ID = "SymbIoTe_Core_AAM";

    // AAM AMQP
    public static final String AAM_EXCHANGE_NAME = "symbIoTe.AuthenticationAuthorizationManager";
    public static final String AAM_VALIDATE_QUEUE = "symbIoTe-AuthenticationAuthorizationManager-validate_request";
    public static final String AAM_VALIDATE_ROUTING_KEY = AAM_EXCHANGE_NAME +
            ".validate_request";
    // TODO DROP THESE 2
    public static final String AAM_LOGIN_QUEUE =
            "symbIoTe-AuthenticationAuthorizationManager-getHomeToken_request";
    public static final String AAM_LOGIN_ROUTING_KEY = AAM_EXCHANGE_NAME +
            ".getHomeToken_request";

    public static final String AAM_GET_AVAILABLE_AAMS = "/get_available_aams";
    public static final String AAM_GET_CLIENT_CERTIFICATE = "/get_client_certificate";
    public static final String AAM_GET_COMPONENT_CERTIFICATE = "/get_component_certificate";
    public static final String AAM_GET_GUEST_TOKEN = "/get_guest_token";
    public static final String AAM_GET_HOME_TOKEN = "/get_home_token";
    public static final String AAM_GET_FOREIGN_TOKEN = "/get_foreign_token";
    public static final String AAM_VALIDATE = "/validate";
    public static final String AAM_MANAGE_USERS = "/manage_users";
    public static final String AAM_MANAGE_PLATFORMS = "/manage_platforms";
    public static final String AAM_REVOKE = "/revoke";

    // errors
    public static final String ERR_WRONG_CREDENTIALS = "ERR_WRONG_CREDENTIALS";

    // tokens
    public static final String TOKEN_HEADER_NAME = "X-Auth-Token";
    public static final int JWT_PARTS_COUNT = 3; //Header, body and signature
    public static final String CLAIM_NAME_TOKEN_TYPE = "ttyp";
    public static final String SUB_NAME_TOKEN_TYPE = "sub";
    public static final String SYMBIOTE_ATTRIBUTES_PREFIX = "SYMBIOTE_";
    public static final String GUEST_NAME = "guest";

    // certificates
    public static final String CLIENT_CERTIFICATE_HEADER_NAME = "X-Auth-Client-Cert";
    public static final String AAM_CERTIFICATE_HEADER_NAME = "X-Auth-AAM-Cert";
    public static final String FOREIGN_TOKEN_ISSUING_AAM_CERTIFICATE = "X-Auth-ISS-Cert";

    // Security Request Headers
    public static final String SECURITY_CREDENTIALS_TIMESTAMP_HEADER = "X-Auth-Timestamp";
    public static final String SECURITY_CREDENTIALS_SIZE_HEADER = "X-Auth-Size";
    public static final String SECURITY_CREDENTIALS_HEADER_PREFIX = "X-Auth-";


    private SecurityConstants() {
    }
}