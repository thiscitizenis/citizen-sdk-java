package is.citizen.sdk.util;

public final class Constant {
    private Constant() {
    }

    public static final String  CITIZEN_PRODUCTION_API_HOST               = "api.citizen.is";
    public static final int     CITIZEN_PRODUCTION_API_PORT               = 443;
    public static final boolean CITIZEN_PRODUCTION_API_SECURE             = true;

    public static final String  CITIZEN_DEVELOPMENT_API_HOST               = "development.citizen.is";
    public static final int     CITIZEN_DEVELOPMENT_API_PORT               = 443;
    public static final boolean CITIZEN_DEVELOPMENT_API_SECURE             = true;

    public static final String  CITIZEN_USER_RESOURCE                      = "users",
                                CITIZEN_SESSION_RESOURCE                   = "sessions",
                                CITIZEN_TOKEN_RESOURCE                     = "tokens",
                                CITIZEN_PERSON_RESOURCE                    = "persons",
                                CITIZEN_PHONE_RESOURCE                     = "phones",
                                CITIZEN_WEBAPP_RESOURCE                    = "webapp",
                                CITIZEN_ENTITY_RESOURCE                    = "entities",
                                CITIZEN_PUBLIC_RESOURCE                    = "public";

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
