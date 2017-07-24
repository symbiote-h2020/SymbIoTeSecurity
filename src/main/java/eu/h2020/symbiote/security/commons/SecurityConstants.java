package eu.h2020.symbiote.security.commons;

/**
 * Constants related to SH-AAM communication
 *
 * TODO R3 review to remove obsolete values
 * @author Mikołaj Dobski (PSNC)
 */
public class SecurityConstants {
    public static final long serialVersionUID = 7526472295622776147L;

    // Security GLOBAL
    public static final String CURVE_NAME = "secp256r1";
    public static final String KEY_PAIR_GEN_ALGORITHM = "ECDSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    public static final String ENCRYPTION_ALGORITHM = "RSA";

    // AAM GLOBAL
    public static final String AAM_CORE_AAM_FRIENDLY_NAME = "SymbIoTe Core AAM";
    public static final String AAM_CORE_AAM_INSTANCE_ID = "SymbIoTe_Core_AAM";
    public static final String COMPONENT_ID = "SymbIoTe_Component";

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

    // AAM REST
    public static final String AAM_ADMIN_PATH = "/admin";
    public static final String AAM_GET_AVAILABLE_AAMS = "/get_available_aams";
    public static final String AAM_GET_CLIENT_CERTIFICATE = "/get_client_certificate";
    public static final String AAM_GET_COMPONENT_CERTIFICATE = "/get_component_certificate";
    public static final String AAM_GET_GUEST_TOKEN = "/get_guest_token";
    public static final String AAM_GET_HOME_TOKEN = "/get_home_token";
    public static final String AAM_GET_FOREIGN_TOKEN = "/get_foreign_token";
    public static final String AAM_PUBLIC_PATH = "/public";
    public static final String AAM_VALIDATE = "/validate";

    // errors
    public static final String ERR_MISSING_ARGUMENTS = "ERR_MISSING_ARGUMENTS";
    public static final String ERR_TOKEN_EXPIRED = "TOKEN_EXPIRED";
    public static final String ERR_WRONG_CREDENTIALS = "ERR_WRONG_CREDENTIALS";
    public static final String ERR_TOKEN_WRONG_ISSUER = "TOKEN_WRONG_ISSUER";
    public static final String ERROR_WRONG_TOKEN = "ERR_WRONG_TOKEN";

    // tokens
    public static final String TOKEN_HEADER_NAME = "X-Auth-Token";
    public static final int JWTPartsCount = 3; //Header, body and signature
    public static final String CLAIM_NAME_TOKEN_TYPE = "ttyp";
    public static final String SYMBIOTE_ATTRIBUTES_PREFIX = "SYMBIOTE_";
    public static final String GUEST_NAME = "guest";

    // certificates
    public static final String CERTIFICATE_HEADER_NAME = "X-Auth-Cert";


    private SecurityConstants() {
    }
}