package eu.h2020.symbiote.security.commons;

/**
 * Constants related to SH-AAM communication
 * <p>
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
    public static final String CORE_AAM_FRIENDLY_NAME = "SymbIoTe Core AAM";
    public static final String CORE_AAM_INSTANCE_ID = "SymbIoTe_Core_AAM";
    public static final String PLATFORM_AGENT_IDENTIFIER_PREFIX = "PA_";
    public static final String SMART_SPACE_IDENTIFIER_PREFIX = "SSP_";

    // component certificates resolver constants
    public static final String AAM_COMPONENT_NAME = "aam";

    // AAM REST paths
    public static final String AAM_GET_AVAILABLE_AAMS = "/get_available_aams";
    public static final String AAM_GET_AAMS_INTERNALLY = "/get_internally_aams";
    public static final String AAM_GET_COMPONENT_CERTIFICATE = "/get_component_certificate";
    public static final String AAM_GET_FOREIGN_TOKEN = "/get_foreign_token";
    public static final String AAM_GET_GUEST_TOKEN = "/get_guest_token";
    public static final String AAM_GET_HOME_TOKEN = "/get_home_token";
    public static final String AAM_GET_USER_DETAILS = "/get_user_details";
    public static final String AAM_MANAGE_PLATFORMS = "/manage_platforms";
    public static final String AAM_MANAGE_USERS = "/manage_users";
    public static final String AAM_REVOKE_CREDENTIALS = "/revoke_credentials";
    public static final String AAM_SIGN_CERTIFICATE_REQUEST = "/sign_certificate_request";
    public static final String AAM_VALIDATE_CREDENTIALS = "/validate_credentials";
    public static final String AAM_VALIDATE_FOREIGN_TOKEN_ORIGIN_CREDENTIALS = "/validate_foreign_token_origin_credentials";


    // tokens
    public static final String TOKEN_HEADER_NAME = "x-auth-token";
    public static final int JWT_PARTS_COUNT = 3; //Header, body and signature
    public static final String CLAIM_NAME_TOKEN_TYPE = "ttyp";
    public static final String SYMBIOTE_ATTRIBUTES_PREFIX = "SYMBIOTE_";
    public static final String FEDERATION_CLAIM_KEY_PREFIX = "federation_";
    public static final String GUEST_NAME = "guest";

    // certificates
    public static final String CLIENT_CERTIFICATE_HEADER_NAME = "x-auth-client-cert";
    public static final String AAM_CERTIFICATE_HEADER_NAME = "x-auth-aam-cert";
    public static final String FOREIGN_TOKEN_ISSUING_AAM_CERTIFICATE = "x-auth-iss-cert";

    // Security Request Headers
    public static final String SECURITY_CREDENTIALS_TIMESTAMP_HEADER = "x-auth-timestamp";
    public static final String SECURITY_CREDENTIALS_SIZE_HEADER = "x-auth-size";
    public static final String SECURITY_CREDENTIALS_HEADER_PREFIX = "x-auth-";
    public static final String SECURITY_RESPONSE_HEADER = "x-auth-response";

    public static final String ADM_LOG_FAILED_FEDERATION_AUTHORIZATION = "/log_failed_federation_authorization";
    public static final String ADM_GET_FEDERATED_MISDEEDS = "/federated_misdeeds";

    //Access Policy JSON fields
    //Single Token
    public static final String ACCESS_POLICY_JSON_FIELD_TYPE = "policyType";
    public static final String ACCESS_POLICY_JSON_FIELD_CLAIMS = "requiredClaims";

    //Composite AP
    public static final String ACCESS_POLICY_JSON_FIELD_OPERATOR = "relationOperator";
    public static final String ACCESS_POLICY_JSON_FIELD_SINGLE_TOKEN_AP = "singleTokenAccessPolicySpecifiers";
    public static final String ACCESS_POLICY_JSON_FIELD_COMPOSITE_AP = "compositeAccessPolicySpecifiers";

    public static final String ERROR_DESC_UNSUPPORTED_ACCESS_POLICY_TYPE = "Access policy type not suppoted!";
    private SecurityConstants() {
    }
}