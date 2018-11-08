package is.citizen.sdk.util;

public final class Constant {
    private Constant() {
    }

    public static final String  CITIZEN_PRODUCTION_API_HOST                = "api.citizen.is";
    public static final int     CITIZEN_PRODUCTION_API_PORT                = 443;
    public static final boolean CITIZEN_PRODUCTION_API_USE_TLS             = true;

    public static final String  CITIZEN_DEVELOPMENT_API_HOST               = "testapi.citizen.is";
    public static final int     CITIZEN_DEVELOPMENT_API_PORT               = 443;
    public static final boolean CITIZEN_DEVELOPMENT_API_USE_TLS            = true;

    public static final String  CITIZEN_LOCAL_API_HOST                     = "localhost";
    public static final int     CITIZEN_LOCAL_API_PORT                     = 8443;
    public static final boolean CITIZEN_LOCAL_API_USE_TLS                  = true;

    private static final String CITIZEN_API_VERSION                        = "v1";

    public static final String  CITIZEN_USER_RESOURCE                      = CITIZEN_API_VERSION + "/users",
                                CITIZEN_SESSION_RESOURCE                   = CITIZEN_API_VERSION + "/sessions",
                                CITIZEN_TOKEN_RESOURCE                     = CITIZEN_API_VERSION + "/tokens",
                                CITIZEN_PERSON_RESOURCE                    = CITIZEN_API_VERSION + "/persons",
                                CITIZEN_PHONE_RESOURCE                     = CITIZEN_API_VERSION + "/phones",
                                CITIZEN_WEBAPP_RESOURCE                    = CITIZEN_API_VERSION + "/webapp",
                                CITIZEN_ENTITY_RESOURCE                    = CITIZEN_API_VERSION + "/entities",
                                CITIZEN_PUBLIC_RESOURCE                    = CITIZEN_API_VERSION + "/public";

    public static final String  CITIZEN_AUTHORISATION_HEADER_NAME          = "AuthorizationCitizen",
                                CITIZEN_SECRET_HEADER_NAME                 = "X-code",
                                CITIZEN_SIGNATURE_HEADER_NAME              = "X-signature";


    public static final int     CITIZEN_REST_SUCCESS                       = 200,
                                CITIZEN_REST_INFO                          = 0,
                                CITIZEN_REST_GENERAL_ERROR                 = -1,
                                CITIZEN_CRYPTO_SUCCESS                     = 1,
                                CITIZEN_CRYPTO_ERROR                       = -1,
                                CITIZEN_STOMP_INFO                         = 0,
                                CITIZEN_STOMP_ERROR                        = -1,
                                CITIZEN_GENERAL_INFO                       = 0;

    public static final String  CITIZEN_SORT                               = "sort",
                                CITIZEN_SORT_STATUS                        = "sortStatus",
                                CITIZEN_SORT_DATE                          = "sortDate",
                                CITIZEN_SORT_TYPE                          = "sortType";

    public static final String  CITIZEN_JWT_AUTHENTICATED_CLAIM            = "is.citizen.authenticated";
}
