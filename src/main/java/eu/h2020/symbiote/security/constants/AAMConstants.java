package eu.h2020.symbiote.security.constants;

/**
 * Constants related to SH-AAM communication
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class AAMConstants {
    public static final long serialVersionUID = 7526472295622776147L;
    // AAM GLOBAL
    public static final String AAM_CORE_AAM_FRIENDLY_NAME = "SymbIoTe Core AAM";
    public static final String AAM_CORE_AAM_INSTANCE_ID = "SymbIoTe_Core_AAM";

    // AAM AMQP
    public static final String AAM_EXCHANGE_NAME = "symbIoTe.AuthenticationAuthorizationManager";
    public static final String AAM_CHECK_REVOCATION_QUEUE =
            "symbIoTe-AuthenticationAuthorizationManager-check_token_revocation_request";
    public static final String AAM_CHECK_REVOCATION_ROUTING_KEY = "symbIoTe.AuthenticationAuthorizationManager" +
            ".check_token_revocation_request";
    public static final String AAM_LOGIN_QUEUE =
            "symbIoTe-AuthenticationAuthorizationManager-login_request";
    public static final String AAM_LOGIN_ROUTING_KEY = "symbIoTe.AuthenticationAuthorizationManager" +
            ".login_request";

    // AAM REST
    public static final String AAM_ADMIN_PATH = "/admin";
    public static final String AAM_CHECK_HOME_TOKEN_REVOCATION = "/check_home_token_revocation";
    public static final String AAM_GET_AVAILABLE_AAMS = "/get_available_aams";
    public static final String AAM_GET_CA_CERTIFICATE = "/get_ca_cert";
    public static final String AAM_LOGIN = "/login";
    public static final String AAM_PUBLIC_PATH = "/public";
    public static final String AAM_REQUEST_FOREIGN_TOKEN = "/request_foreign_token";

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

    private AAMConstants() {
    }
}