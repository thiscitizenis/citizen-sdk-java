package is.citizen.sdk.api;

import com.fasterxml.jackson.databind.node.TextNode;
import is.citizen.sdk.crypto.CitizenCrypto;
import is.citizen.sdk.crypto.KeyHolder;
import is.citizen.sdk.enums.*;
import is.citizen.sdk.exception.CryptoException;
import is.citizen.sdk.exception.RestException;
import is.citizen.sdk.resource.*;
import is.citizen.sdk.util.Constant;
import is.citizen.sdk.util.RestClient;
import is.citizen.sdk.util.WebStompClient;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.springframework.web.client.HttpStatusCodeException;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class CitizenApi implements WebStompClient.LoggingCallback {
    public interface LoggingCallback {
        void loggingCallback(int status, String message);
    }

    public interface JwtOverStompCallback {
        void jwtOverStompCallback(String jwt);
    }

    private String apiHost = Constant.CITIZEN_PRODUCTION_API_HOST;
    private int apiPort = Constant.CITIZEN_PRODUCTION_API_PORT;
    private boolean apiSecure = Constant.CITIZEN_PRODUCTION_API_USE_TLS;

    private RestClient restClient;
    private CitizenCrypto citizenCrypto;

    private boolean debug = false;

    private String apiKey = null;
    private String secret = null;
    private String signature = null;

    public CitizenApi() {
        restClient = new RestClient();
        restClient.setApiHost(apiHost);
        restClient.setApiPort(apiPort);
        restClient.setApiSecure(apiSecure);

        citizenCrypto = new CitizenCrypto();
    }

    private List<LoggingCallback> loggingCallbacks = new ArrayList<LoggingCallback>();

    private List<JwtOverStompCallback> jwtOverStompCallbacks = new ArrayList<JwtOverStompCallback>();

    public void registerLoggingCallback(LoggingCallback callback) {
        loggingCallbacks.add(callback);
    }

    private void log(int status, String errorMessage) {
        for (LoggingCallback loggingCallback : loggingCallbacks) {
            loggingCallback.loggingCallback(status, errorMessage);
        }
    }

    /**
     * Generate an EC secp256r1 key for use with authentication and signing.
     *
     * @return {@link KeyHolder} containing the public and private keys or empty Optional upon error.
     */

    public Optional<KeyHolder> generateAuthKeyPair(String password) {

        if (debug) {
            log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Creating auth key pair.");
        }

        try {
            KeyHolder keyHolder = citizenCrypto.generateAuthenticationKeyPair(password);
            log(Constant.CITIZEN_CRYPTO_SUCCESS, "INFO: generated auth key pair");
            return Optional.of(keyHolder);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Generate a RSA 2048 bit key for use with encryption and decryption.
     *
     * @return Optional {@link KeyHolder} containing the public and private keys or empty Optional upon error.
     */

    public Optional<KeyHolder> generateCryptoKeyPair(String password) {

        if (debug) {
            log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Creating crypto key pair.");
        }

        try {
            KeyHolder keyHolder = citizenCrypto.generateCryptoKeyPair(password);
            log(Constant.CITIZEN_CRYPTO_SUCCESS, "INFO: generated crypto key pair");
            return Optional.of(keyHolder);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Convert an authentication public key from the Citizen Service into a Java {@link PublicKey}
     *
     * @param publicKeyString authentication public key in Base 64 encoded DER format.
     *
     * @return Optional {@link PublicKey} converted public key or empty Optional upon error.
     */
    public Optional<PublicKey> convertAuthPublicKeyStringToJava(String publicKeyString) {

        try {
            PublicKey publicKey = citizenCrypto.getPublicAuthKeyFromEncodedString(publicKeyString);
            return Optional.of(publicKey);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Convert an encrypted authentication private key from the Citizen Service into a Java {@link PrivateKey}
     *
     * @param privateKeyString encrypted authentication private key.
     * @param password password for the encrypted private key
     *
     * @return Optional {@link PrivateKey} converted private key or empty Optional upon error.
     */
    public Optional<PrivateKey> convertAuthPrivateKeyStringToJava(String privateKeyString, String password) {

        try {
            PrivateKey privateKey = citizenCrypto.getPrivateAuthKeyFromEncodedEncryptedString(privateKeyString, password);
            return Optional.of(privateKey);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Convert an crypto public key from the Citizen Service into a Java {@link PublicKey}
     *
     * @param publicKeyString crypto public key in Base 64 encoded DER format.
     *
     * @return Optional {@link PublicKey} converted public key or empty Optional upon error.
     */
    public Optional<PublicKey> convertCryptoPublicKeyStringToJava(String publicKeyString) {

        try {
            PublicKey publicKey = citizenCrypto.getPublicCryptoKeyFromEncodedString(publicKeyString);
            return Optional.of(publicKey);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Convert an encrypted crypto private key from the Citizen Service into a Java {@link PrivateKey}
     *
     * @param privateKeyString encrypted crypto private key.
     * @param password password for the encrypted private key
     *
     * @return Optional {@link PrivateKey} converted private key or empty Optional upon error.
     */
    public Optional<PrivateKey> convertCryptoPrivateKeyStringToJava(String privateKeyString, String password) {

        try {
            PrivateKey privateKey = citizenCrypto.getPrivateCryptoKeyFromEncodedEncryptedString(privateKeyString, password);
            return Optional.of(privateKey);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Create a third party entity.
     *
     * @param email email address for the {@link Entity}
     * @param password password for the {@link Entity}.
     * @param passPhrase pass phrase for the {@link Entity}.
     * @param name name of the {@link Entity}.
     * @param adminEmail email address of the {@link Entity} first admin account.
     * @param adminPassword password of the {@link Entity} first admin account.
     * @param tradingName  {@link Entity} trading name.
     * @param companyNumber {@link Entity} company number.
     * @param addressLine1  {@link Entity} address line 1.
     * @param addressLine2 {@link Entity} address line 2.
     * @param addressLine3 {@link Entity} address line 3.
     * @param city {@link Entity} city (address).
     * @param addressCountryName {@link Entity} country (address).
     * @param postcode {@link Entity} post code (address).
     * @param phoneNumber {@link Entity} phone number.
     * @param phoneCountryCode {@link Entity} phone country code.
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> createEntity(String username,
                                         String email,
                                         String password,
                                         String passPhrase,
                                         String name,
                                         String adminEmail,
                                         String adminPassword,
                                         String tradingName,
                                         String companyNumber,
                                         String addressLine1,
                                         String addressLine2,
                                         String addressLine3,
                                         String city,
                                         CountryName addressCountryName,
                                         String postcode,
                                         String phoneNumber,
                                         CountryCode phoneCountryCode) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Creating entity: " +
                     "(username: " + username + ", " +
                     "email: " + email + ", " +
                     "password: " + password + ", " +
                     "passPhrase: " + passPhrase + ", " +
                     "name: " + name + ", " +
                     "adminEmail: " + adminEmail + ", " +
                     "adminPassword: " + adminPassword + ", " +
                     "tradingName: " + tradingName + ", " +
                     "companyNumber: " + companyNumber + ", " +
                     "addressLine1: " + addressLine1 + ", " +
                     "addressLine2: " + addressLine2 + ", " +
                     "addressLine3: " + addressLine3 + ", " +
                     "city: " + city + ", " +
                     "addressCountryName: " + addressCountryName.toString() + ", " +
                     "postcode: " + postcode + ", " +
                     "phoneNumber: " + phoneNumber + ", " +
                     "phoneCountryCode: " + phoneCountryCode.toString() + ")");
        }

        Address address = new Address();
        address.setAddressLine1(addressLine1);
        address.setAddressLine2(addressLine2);
        address.setAddressLine3(addressLine3);
        address.setCity(city);
        address.setCountryName(addressCountryName);
        address.setPostCode(postcode);
        address.setAddressType(AddressType.OFFICE);

        Phone phone = new Phone();
        phone.setPhoneNumber(phoneNumber);
        phone.setCountryCode(phoneCountryCode);
        phone.setPhoneType(PhoneType.WORK);

        Entity entity = new Entity();
        entity.setUsername(username);
        entity.setEmail(email);
        entity.setPassword(password);
        entity.setPassPhrase(passPhrase);
        entity.setName(name);
        entity.setAdminEmail(adminEmail);
        entity.setAdminPassword(adminPassword);
        entity.setAdminPassword(password);
        entity.setTradingName(tradingName);
        entity.setCompanyNumber(companyNumber);
        entity.setAddress(address);
        entity.setPhone(phone);

        restClient.clearApiHeaders();

        try {
            entity = restClient.post(Constant.CITIZEN_ENTITY_RESOURCE, entity, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Entity created: Id: " + entity.getId());
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Get an entity.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> getEntity(String entityId) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Get entity: " + entityId);
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            Entity entity = restClient.get(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got entity: " + entity.getId());
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Add a web hook to an entity.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     * @param eventType bitmask of {@link EventType} values
     * @param url URL of the web hook
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> addEntityWebHook(String entityId, int eventType, String url) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Add entity web hook: " +
                     "(entityId: " + entityId + ", " +
                     "eventType: " + eventType  +", " +
                     "url: " + url + ")");
        }

        WebHook webHook = new WebHook();
        webHook.setType(eventType);
        webHook.setUrl(url);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            Entity entity = restClient.put(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/webHook", webHook, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: added entity web hook: url: " + url);
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Remove a web hook from an entity.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     * @param eventType bitmask of {@link EventType} values
     * @param url URL of the web hook
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> removeEntityWebHook(String entityId, int eventType, String url) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Remove entity web hook: " +
                     "(entityId: " + entityId + ", " +
                     "eventType: " + eventType  +", " +
                     "url: " + url + ")");
        }

        WebHook webHook = new WebHook();
        webHook.setType(eventType);
        webHook.setUrl(url);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            Entity entity = restClient.delete(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/webHook", webHook, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: removed entity web hook: " + url);
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Add a user to an entity.
     *
     * Note that the userEmail passed here must be first added as the user's entity email with the
     * setUserEntity() call.
     *
     * This call requires an entity or entityAdmin apiKey and secret attributes to be set. They can
     * be set with the setApiKey() method.setSecret() methods respectively.
     *
     * @param entityId ID of the {@link Entity}
     * @param userEntityEmail user's entity email. This must be the same as the email address used in the
     *                  setUserEntity() call.
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> addEntityUser(String entityId, String userEntityEmail) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Add user to entity: " +
                     "(entityId: " + entityId + ", " +
                     "userEmail: " + userEntityEmail + ")");
        }

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return Optional.empty();
        }

        User entityUser = new User();
        entityUser.setEntityEmail(userEntityEmail);
        entityUser.setIsAdmin(false);

        try {
            Entity entity = restClient.patch(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/entity-user", entityUser, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: added user: " + userEntityEmail + " to entity: " + entityId);
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Remove a user from an entity.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     * @param hashedEntityEmail hashed email of the {@link User}
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> removeEntityUser(String entityId, String hashedEntityEmail) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Remove user from entity: " +
                     "(entityId: " + entityId + ", " +
                     "hashedUserEmail: " + hashedEntityEmail + ")");
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            Entity entity = restClient.delete(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/entity-user/" + hashedEntityEmail, null, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: removed user: " + hashedEntityEmail + " from entity: " + entityId);
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Update the admin status of an entity user.
     *
     * This call requires an entity or entityAdmin apiKey and secret attributes to be set. They can
     * be set with the setApiKey() method.setSecret() methods respectively.
     *
     * @param entityId ID of the {@link Entity}
     * @param personId Person ID of the {@link User}
     * @param isAdmin boolean determining the user's admin status.
     *
     * @return Optional {@link Entity}
     */
    @Deprecated
    public Optional<Entity> updateEntityAdmin(String entityId, String personId, boolean isAdmin) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Update entity user admin status: " +
                     "(entityId: " + entityId + ", " +
                     "personId: " + personId + ", " +
                     "isAdmin: " + isAdmin + ")");
        }

        restClient.clearApiHeaders();
        restClient.setApiKey(apiKey);
        restClient.setSecret(secret);

        try {
            Entity entity = restClient.patch(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/users/" + personId + "/updateAdmin", isAdmin, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO updated entity user: " + personId + " for entity: " + entityId + " to admin status: " + isAdmin);
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Get a list of {@link Entity} users.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     *
     * @return Optional {@link EntityUserDetailsWrapper}
     */
    public Optional<EntityUserDetailsWrapper> getEntityUsers(String entityId) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Get entity users for entity: " + entityId);
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            EntityUserDetailsWrapper userDetailsWrapper = restClient.get(
                Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/users", EntityUserDetailsWrapper.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got entity users for entity: " + entityId);
            return Optional.of(userDetailsWrapper);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Regenerate the entity's signing private key.
     *
     * The corresponding public key can be obtained from the returned {@link Entity} object.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> regenerateEntitySigningKey(String entityId) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Regenerate entity signing key for entity: " + entityId);
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            Entity entity = restClient.put(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/regenerateSigningKey", null, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Regenerated signing key for entity: " + entityId);
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Register a crypto public key.
     *
     * The key must be an RSA 2048 bit key and passed as a Base 64 encoded DER string.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     * @param cryptoPublicKey Base 64 encoded DER string of the public key.
     */
    public void registerEntityCryptoPublicKey(String entityId, String cryptoPublicKey) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Register Crypto public key for entity: " + entityId);
        }

        Entity entity = new Entity();
        entity.setId(entityId);
        entity.setCryptoPublicKey(cryptoPublicKey);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return;
        }

        try {
            restClient.put(Constant.CITIZEN_ENTITY_RESOURCE + "/registerPublicKey", entity, Void.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Registered public key for entity: " + entityId);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }
    }

    /**
     * Register a data agreement for an entity.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity}
     * @param duration Duration of the agreement
     * @param durationType unit of the agreement duration (days, months, years etc): {@link TokenDurationType}
     * @param agreementName Name of the agreement
     * @param agreementPurpose Agreement purpose
     * @param sharedTo List of entity names (companies etc) that the data is shared with.
     *
     * @return Optional {@link Entity}
     */
    public Optional<Entity> registerDataAgreement(String entityId,
                                                  int duration,
                                                  TokenDurationType durationType,
                                                  String agreementName,
                                                  String agreementPurpose,
                                                  List<String> sharedTo) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Register entity data agreement: " +
                     "entityId: " + entityId + ", " +
                     "duration: " + duration + ", " +
                     "durationType: " + durationType.toString() + ", " +
                     "agreementName: " + agreementName + ", " +
                     "agreementPurpose: " + agreementPurpose + ", " +
                     "sharedTo: " + sharedTo.toArray().toString() + ")");
        }

        DataAgreement dataAgreement = new DataAgreement();
        dataAgreement.setDuration(duration);
        dataAgreement.setDurationType(durationType);
        dataAgreement.setName(agreementName);
        dataAgreement.setPurpose(agreementPurpose);
        dataAgreement.setSharedTo(sharedTo);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            Entity entity = restClient.put(Constant.CITIZEN_ENTITY_RESOURCE + "/" + entityId + "/registerDataAgreement", dataAgreement, Entity.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Registered data agreement: " + agreementName + " for entity: " + entityId);
            return Optional.of(entity);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Register an entity {@link GreyUser}
     *
     * The values of these parameters may be null. The call will set the user's data once minimum conditions
     * are met.
     *
     * This call requires the entity public apiKey attribute to be set. It can be set with the
     * setApiKey() method.
     *
     * @param userEmail email address for the new {@link GreyUser}
     * @param firstName first name of the new {@link GreyUser}
     * @param middleName middle name of the new {@link GreyUser}
     * @param lastName last name of the new {@link GreyUser}
     * @param title title of the new {@link GreyUser}
     * @param gender gender of the new {@link GreyUser}
     * @param dateOfBirth date of birth of the new {@link GreyUser}
     * @param addressLine1 {@link GreyUser} address line 1
     * @param addressLine2 {@link GreyUser} address line 2
     * @param addressLine3 {@link GreyUser} address line 3
     * @param city {@link GreyUser} city (address)
     * @param addressCountryName {@link GreyUser} country
     * @param postcode {@link GreyUser} postcode (address)
     * @param addressType {@link GreyUser} address type (home, office etc)
     * @param phoneNumber {@link GreyUser} phone number
     * @param phoneCountryCode {@link GreyUser} phone country code
     * @param phoneType {@link GreyUser} (home, office, mobile)
     *
     * @return Optional {@link GreyUser}
     */
    public Optional<GreyUser> registerEntityUser(String userEmail,
                                                 String firstName,
                                                 String middleName,
                                                 String lastName,
                                                 String title,
                                                 String gender,
                                                 DateTime dateOfBirth,
                                                 String addressLine1,
                                                 String addressLine2,
                                                 String addressLine3,
                                                 String city,
                                                 CountryName addressCountryName,
                                                 String postcode,
                                                 AddressType addressType,
                                                 String phoneNumber,
                                                 CountryCode phoneCountryCode,
                                                 PhoneType phoneType) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Register entity user: " +
                     "userEmail: " + userEmail + ", " +
                     "firstName: " + firstName + ", " +
                     "middleName: " + middleName + ", " +
                     "lastName: " + lastName + ", " +
                     "gender: " + gender + ", " +
                     "dateOfBirth: " + dateOfBirth.toString() + ", " +
                     "addressLine1: " + addressLine1 + ", " +
                     "addressLine2: " + addressLine2 + ", " +
                     "addressLine3: " + addressLine3 + ", " +
                     "city: " + city + ", " +
                     "addressCountryName: " + addressCountryName.toString() + ", " +
                     "postCode: " + postcode + ", " +
                     "addressType: " + addressType + ", " +
                     "phoneCountryCode: " + phoneCountryCode.toString() + ", " +
                     "phoneType: " + phoneType.toString() + ")");
        }

        GreyUser greyUser = new GreyUser();
        greyUser.setPrimaryEmail(userEmail);

        if (firstName != null && lastName != null) {
            greyUser.setFirstName(firstName);
            greyUser.setMiddleName(middleName);
            greyUser.setLastName(lastName);
            greyUser.setTitle(title);
        }

        if (gender != null) {
            greyUser.setGender(gender);
        }

        if (dateOfBirth != null) {
            greyUser.setDateOfBirth(dateOfBirth);
        }

        if (addressLine1 != null &&
            city != null &&
            addressCountryName != null &&
            postcode != null &&
            addressType != null) {
            Address address = new Address();
            address.setAddressLine1(addressLine1);
            address.setAddressLine2(addressLine2);
            address.setAddressLine3(addressLine3);
            address.setCity(city);
            address.setCountryName(addressCountryName);
            address.setPostCode(postcode);
            address.setAddressType(addressType);

            greyUser.setAddress(address);
        }

        if (phoneNumber != null &&
            phoneCountryCode != null &&
            phoneType != null) {
            Phone phone = new Phone();
            phone.setPhoneNumber(phoneNumber);
            phone.setCountryCode(phoneCountryCode);
            phone.setPhoneType(phoneType);

            greyUser.setPhone(phone);
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            greyUser = restClient.post(Constant.CITIZEN_ENTITY_RESOURCE + "/registerUser", greyUser, GreyUser.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Registered entity user: " + userEmail);
            return Optional.of(greyUser);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Check if an entity user exists.
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param userEmail email address of the entity user.
     *
     * @return Optional {@link UserCheck}
     */
    public Optional<UserCheck> checkEntityUserExists(String userEmail) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Check if user exists: " + userEmail);
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        TextNode userEmailTextNode = new TextNode(userEmail);

        try {
            UserCheck userCheck = restClient.post(Constant.CITIZEN_ENTITY_RESOURCE + "/checkUserExists", userEmailTextNode, UserCheck.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Checked if user exists: " + userEmail);
            return Optional.of(userCheck);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Get the public API key of an {@link Entity}
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @return Optional String
     */
    public Optional<String> getEntityPublicApiKey() {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Get entity public API key");
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            String publicApiKey = restClient.get(Constant.CITIZEN_ENTITY_RESOURCE + "/publicApiKey", String.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got entity API key");
            return Optional.of(publicApiKey);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Create a Citizen {@link User}
     *
     * The auth public key here is a EC secp256r1 key. It is passed in Base 64 encoded DER format.
     * It is not necessary to pass the auth key when creating the user.
     *
     * @param username username of the new {@link User}
     * @param primaryEmail email of the new {@link User}
     * @param passPhrase new {@link User} passphrase
     * @param authPublicKey auth public key for the new {@link User}
     *
     * @return Optional {@link User}
     */
    public Optional<User> createUser(String username,
                                     String primaryEmail,
                                     String passPhrase,
                                     String authPublicKey) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Create user: " +
                     "username: " + username + ", " +
                     "primaryEmail: " + primaryEmail + ", " +
                     "passPhrase: XXXXXXXX, " +
                     "authPublicKey: XXXXXXXX)");
        }

        User user = new User();
        user.setUsername(username);
        user.setPrimaryEmail(primaryEmail);
        if (passPhrase != null) {
            user.setPassPhrase(passPhrase);
        }
        if (authPublicKey != null) {
            user.setAuthPublicKey(authPublicKey);
        }

        restClient.clearApiHeaders();

        try {
            user = restClient.post(Constant.CITIZEN_USER_RESOURCE, user, User.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Created user: " + username);
            return Optional.of(user);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Log in by signing a nonce with the user's private auth key.
     *
     * This is a EC secp256r1 key. The corresponding public key must be registered for this call
     * to succeed.
     *
     * @param username username of the {@link User}
     * @param privateKey {@link User} private auth key
     * @param keyPassword password for the {@link User} private auth key
     *
     * @return Optional {@link User}
     */
    public Optional<User> loginWithSignature(String username,
                                             String privateKey,
                                             String keyPassword) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Log in with signature: " +
                     "username: " + username + ", " +
                     "privateKey: XXXXXXXX, " +
                     "keyPassword: XXXXXXXX)");
        }

        String nonce;
        try {
            nonce = restClient.get(Constant.CITIZEN_WEBAPP_RESOURCE + "/login/web/getSessionNonce", String.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got nonce");
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
            return Optional.empty();
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
            return Optional.empty();
        }

        LoginTransaction loginTransaction = new LoginTransaction(username, nonce);

        String singedTransaction = "";
        try {
            singedTransaction = citizenCrypto.signData(loginTransaction.toByteArray(), privateKey, keyPassword);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
            return Optional.empty();
        }

        restClient.clearApiHeaders();
        restClient.setSignature(singedTransaction);

        try {
            User user = restClient.post(Constant.CITIZEN_SESSION_RESOURCE + "/auth", loginTransaction, User.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: logged in with signature: " + username);
            return Optional.of(user);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Log in using a username and password.
     *
     * @param username username of the {@link User}
     * @param password password of the {@link User}
     *
     * @return Optionl {@link User}
     */
    public Optional<User> loginWithUsernameAndPassword(String username, String password) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Log in with password: " +
                     "username: " + username + ", " +
                     "password: XXXXXXXX)");
        }

        restClient.clearApiHeaders();

        User user = new User();
        user.setPrimaryEmail(username);
        user.setPassword(password);

        try {
            user = restClient.post(Constant.CITIZEN_SESSION_RESOURCE, user, User.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: logged in with password: " + username);
            return Optional.of(user);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Get a Citizen {@User}'s secret.
     *
     * This is used as a password to the user's crypto private key, which resides on the Citizen Service
     * The secret is used as a parameter for some calls for decryption.
     *
     * @param userEmail primary email of the {@link User}
     * @param passPhrase pass phrase of the {@link User}
     *
     * @return Optional String
     */
    public Optional<String> getUserSecret(String userEmail, String passPhrase) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Get user secret: " +
                     "userEmail: " + userEmail + ", " +
                     "passPhrase: XXXXXXXX)");
        }

        restClient.clearApiHeaders();

        User user = new User();
        user.setPrimaryEmail(userEmail);
        user.setPassPhrase(passPhrase);

        try {
            String secret = restClient.post(Constant.CITIZEN_SESSION_RESOURCE + "/mnemonic", user, String.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got secret for user: " + userEmail);
            return Optional.of(secret);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Register a user's authentication public key.
     *
     * This call requires the user's apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param userId ID of the {@link User}
     * @param authPublicKey Base 64 encoded DER representation of the public key.
     */
    public void registerUserAuthPublicKey(String userId, String authPublicKey) {
        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Register user auth public key: " +
                     "userId: " + userId + ", " +
                     "authPublicKey: XXXXXXXX)");
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return;
        }

        TextNode authPublicKeyTextNode = new TextNode(authPublicKey);

        try {
            String secret = restClient.post(Constant.CITIZEN_USER_RESOURCE + "/" + userId + "/publicKey", authPublicKeyTextNode, String.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: register auth public key for user: " + userId);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }
    }

    /**
     * Send a token login request from an entity to a user.
     *
     * If the Citizen {@link} user approves the token, a JSON Web Token is sent to the {@link Entity}
     * site via a web socket. The web socket setup and callback are handled in the call:
     *
     *   setupStompClientAndReceiveJwt()
     *
     * This call requires an entity or entityAdmin apiKey attribute to be set. It can be set with
     * the setApiKey() method.
     *
     * @param entityId ID of the {@link Entity} sending the token.
     * @param userEmail email address of the {@link User}
     * @param sessionIdentifier A unique Identifier used by the {@link Entity} to determine the
     *                          session on which the user is attempting to log in.
     *
     * @return Optional String identifier to determine the session on the Citizen Service
     */
    @Deprecated
    public Optional<String> sendJwtLoginTokenToUser(String entityId, String userEmail, String sessionIdentifier) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Send JWT login token to user: " +
                     "entityId: " + entityId + ", " +
                     "userEmail: " + userEmail + ", " +
                     "sessionIdentifier: XXXXXXXX)");
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        String citizenNonce;
        try {
            citizenNonce = restClient.get(Constant.CITIZEN_WEBAPP_RESOURCE + "/login/web/getSessionNonce", String.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got nonce");
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
            return Optional.empty();
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
            return Optional.empty();
        }

        JwtLoginParameters jwtLoginParameters = new JwtLoginParameters();
        jwtLoginParameters.setUserEmail(userEmail);
        jwtLoginParameters.setThirdPartySessionIdentifier(sessionIdentifier);
        jwtLoginParameters.setCitizenSessionNonce(citizenNonce);

        try {
            restClient.post(Constant.CITIZEN_SESSION_RESOURCE + "/entity/authenticate-user-with-token-and-JWT-over-WebSocket", jwtLoginParameters, Void.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Sent JWT login token to user: " + userEmail);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
            return Optional.empty();
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
            return Optional.empty();
        }

        return Optional.of(citizenNonce);
    }

    /**
     * Receive a JSON Web Token authenticating a user on the Citizen Service.
     *
     * The process to authenticate the user must have been started by the call:
     *
     *    sendJwtLoginTokenToUser()
     *
     * This call sets up a web socket to the Citizen Service to receive the JWT. The JWT is sent through
     * the given {@link JwtOverStompCallback} callback.
     *
     * @param nonce the Citizen identifier returned by sendJwtLoginTokenToUser() to identify the session.
     * @param callback {@link JwtOverStompCallback} to receive the JWT.
     */
    @Deprecated
    public void setupStompClientAndReceiveJwt(String nonce, JwtOverStompCallback callback) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Set up STOMP client and receive JWT");
        }

        WebStompClient webStompClient = new WebStompClient();

        webStompClient.setConnectionSecure(false);
        webStompClient.setRemoteHost(apiHost);
        webStompClient.setRemotePort(apiPort);
        webStompClient.setConnectionSecure(apiSecure);
        webStompClient.setStompParametersForJwtFromNonce(nonce);
        webStompClient.registerLoggingCallback(this);

        webStompClient.addListener((state, message, errorMessage) -> {
            if (state == WebStompClient.WEBSTOMPSTATE.FINISHED.toString()) {
                String jwt = message.replaceAll("\"", "");
                log(Constant.CITIZEN_REST_SUCCESS, "INFO: Received JWT");
                callback.jwtOverStompCallback(jwt);
            } else if (state == WebStompClient.WEBSTOMPSTATE.ERROR.toString()) {
                log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: Unable to receive JWT: " + webStompClient.getErrorMessage());
            }
        });

        webStompClient.sendStompMessageAndAwaitResponse();
    }

    /**
     * Set a user's {@link Entity} email address.
     *
     * This address can then be used to add a user to the {@link Entity} with the call:
     *
     *   addEntityUser()
     *
     * This call requires the user's apiKey attribute to be set. It can be set with the setApiKey() method.
     *
     * @param userId ID of the {@link User}
     * @param entityEmail User's entity email address. This must be the same as the addresss used in the
     *                    addEntityUser() call.
     *
     * @return Optional {@link User}
     */

    public Optional<User> setUserEntity(String userId, String entityEmail) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Set user entity: (" +
                     "userId: " + userId + ", " +
                     "entityEmail: " + entityEmail + ")");
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        TextNode entityEmailTextNode = new TextNode(entityEmail);

        try {
            User user = restClient.put(Constant.CITIZEN_USER_RESOURCE + "/" + userId + "/emails/entityEmail", entityEmailTextNode, User.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Entity email set for user: " + userId + " to: " + entityEmail);
            return Optional.of(user);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Create a {@link Token}
     *
     * This call requires a user or entity apiKey and secret attribute to be set. They can be set with the
     * setApiKey() and setSecret() methods respectively.
     *
     * @param userEmail email address of the user to who the {@link Token} is being sent
     * @param access a binary and of {@link AccessType} values
     * @param durationType time unit of the Token duration (days, months etc) {@link TokenDurationType}
     * @param duration duration of the token in durationType units
     *
     * @return Optional {@link Token}
     */
    public Optional<Token> createToken(String userEmail,
                                       int access,
                                       TokenDurationType durationType,
                                       int duration) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Create token: (" +
                     "userEmail: " + userEmail + ", " +
                     "access: " + access + ", " +
                     "durationType: " + durationType.toString() + ", " +
                     "duration: " + duration + ")");
        }

        Token token = new Token();

        token.setTokenStatus(TokenStatus.REQUESTED);
        token.setUserEmail(userEmail);
        token.setAccess(access);
        token.setDurationType(durationType);
        token.setDuration(duration);

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return Optional.empty();
        }

        try {
            token = restClient.post(Constant.CITIZEN_TOKEN_RESOURCE, token, Token.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Created token for user: " + userEmail);
            return Optional.of(token);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Get a {@link Token} by token ID.
     *
     * This call requires a user or entity apiKey and secret attribute to be set. They can be set with the
     * setApiKey() and setSecret() methods respectively.
     *
     * @param tokenId
     *
     * @return Optional {@link Token}
     */
    public Optional<Token> getToken(String tokenId) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Get token: " + tokenId);
        }

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return Optional.empty();
        }

        try {
            Token token = restClient.get(Constant.CITIZEN_TOKEN_RESOURCE + "/" + tokenId, Token.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got token: " + tokenId);
            return Optional.of(token);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Get all tokens sent to a user.
     *
     * This call requires a user or entity apiKey and secret attribute to be set. They can be set with the
     * setApiKey() and setSecret() methods respectively.
     *
     * @return Optional {@link TokenWrapper}
     */
    public Optional<TokenWrapper> getUserTokens() {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Get user tokens");
        }

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return Optional.empty();
        }

        try {
            TokenWrapper tokens = restClient.get(Constant.CITIZEN_TOKEN_RESOURCE + "/user", TokenWrapper.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got user tokens");
            return Optional.of(tokens);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Get all tokens sent by the user.
     *
     * This call requires a user or entity apiKey and secret attribute to be set. They can be set with the
     * setApiKey() and setSecret() methods respectively.
     *
     * @return Optional {@link TokenWrapper}
     */
    public Optional<TokenWrapper> getRequesterTokens() {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Get requester tokens");
        }

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return Optional.empty();
        }

        try {
            TokenWrapper tokens = restClient.get(Constant.CITIZEN_TOKEN_RESOURCE + "/requester", TokenWrapper.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Got requester tokens");
            return Optional.of(tokens);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Grant a token.
     *
     * This call requires a user or entity apiKey and secret attribute to be set. They can be set with the
     * setApiKey() and setSecret() methods respectively.
     *
     * @param token the {@link Token} to grant.
     *
     * @return Optional {@link Token}
     */
    public Optional<Token> grantToken(Token token) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Grant token: " + token.getId());
        }

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return Optional.empty();
        }

        try {
            token = restClient.put(Constant.CITIZEN_TOKEN_RESOURCE + "/" + token.getId() + "/GRANTED", token.getMetaData(), Token.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Granted token: " + token.getId());
            return Optional.of(token);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Decline a {@link Token}
     *
     * This call requires a user or entity apiKey and secret attribute to be set. They can be set with the
     * setApiKey() and setSecret() methods respectively.
     *
     * @param tokenId ID of the {@link Token} to decline.
     *
     * @return Optional {@link Token}
     */
    public Optional<Token> declineToken(String tokenId) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Decline token: " + tokenId);
        }

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return Optional.empty();
        }

        try {
            Token token = restClient.put(Constant.CITIZEN_TOKEN_RESOURCE + "/" + tokenId + "/DECLINED", null, Token.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Declined token" + tokenId);
            return Optional.of(token);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Delete a {@link Token}
     *
     * This call requires a user or entity apiKey and secret attribute to be set. They can be set with the
     * setApiKey() and setSecret() methods respectively.
     *
     * @param tokenId ID of the {@link Token} to delete.
     */
    public void deleteToken(String tokenId) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Delete token: " + tokenId);
        }

        if (apiKey != null && secret != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
            restClient.setSecret(secret);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key or secret not set");
            return;
        }

        try {
            restClient.delete(Constant.CITIZEN_TOKEN_RESOURCE + "/" + tokenId, null, Void.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Deleted token" + tokenId);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }
    }

    /**
     * Sign a {@link Token}
     *
     * The token is signed with a private EC secp256r1 key.
     *
     * The corresponding public key is either given when creating the Citizen {@link User}
     * or with the call:
     *
     *   registerUserAuthPublicKey()
     *
     * The private key is kept by the owner of an  {@link Entity} or a {@link User}.
     * Citizen Service either when the user is created or with the call:
     *
     * @param token {@link Token} to sign
     * @param encodedPrivateKey Base 64 encoded encrypted private key
     *
     * @return Optional {@link Token} signed token.
     */
    public Optional<Token> signToken(Token token, String encodedPrivateKey, String secret) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Sign token: " +
                     "token Id: " + token.getId() + ", " +
                     "encodedPrivateKey: XXXXXXXX, " +
                     "secret: XXXXXXXX");
        }

        try {
            byte[] dataToSign = token.getId().getBytes("utf-8");
            String signedTokenId = citizenCrypto.signData(dataToSign, encodedPrivateKey, secret);

            if (token.getMetaData() == null) {
                token.setMetaData(new HashMap());
            }

            token.getMetaData().put(PropertyType.SIGNED_TOKEN_ID, signedTokenId);
            log(Constant.CITIZEN_CRYPTO_SUCCESS, "INFO: signed token: " + token.getId());
            return Optional.of(token);
        } catch (UnsupportedEncodingException | CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Verify a token signature.
     *
     * This call requires a user or entity apiKey to be set. It can be set with the setApiKey() method.
     *
     * This call gets the user who signed the token from it, fetches their auth public key from
     * the Citizen Service and uses it to verify the signature.
     *
     * @param token signed {@link Token}
     *
     * @return boolean specifying if the verification was successful.
     */
    public boolean verifyTokenSignature(Token token) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Verify token signature: " + token.getId());
        }

        String tokenSignature = (String) token.getMetaData().get(PropertyType.SIGNED_TOKEN_ID);

        if (tokenSignature == null) {
            return false;
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return false;
        }

        String publicKey = restClient.get(Constant.CITIZEN_USER_RESOURCE + "/" + token.getHashedUserEmail() + "/devicePublicKey", String.class);

        boolean result = false;

        try {
            result = citizenCrypto.verifySignature(token.getId().getBytes("utf-8"), Base64.decode(tokenSignature), publicKey);
            log(Constant.CITIZEN_CRYPTO_SUCCESS, "INFO: verified signed token: " + token.getId() + " result: " + restClient);
        } catch (UnsupportedEncodingException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return result;
    }

    /**
     * Decrypt a token's encrypted data.
     *
     * This is for use when decrypting tokens that were encrypted using a Entity's public crypto key.
     *
     * @param token {@link Token} to decrypt.
     * @param privateKey Base 64 encoded encrypted private key.
     * @param secret password for the private key.
     *
     * @return Optional {@link Token} decrypted token.
     */
    public Optional<Token> decryptToken(Token token, String privateKey, String secret) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: decrypt token: " +
                     "token Id: " + token.getId() + ", " +
                     "privateKey: XXXXXXXX, " +
                     "secret: XXXXXXXX)");
        }

        try {
            Optional<Map<String, String>> decMap = citizenCrypto.decryptMap(token.getMetaData(), privateKey, secret);
            decMap.ifPresent(token::setMetaData);
            log(Constant.CITIZEN_CRYPTO_SUCCESS, "INFO: decrypted token: " + token.getId());
            return Optional.of(token);
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Verify a Citizen JSON Web Token.
     *
     * @param jwt JWT to be verified
     * @param publicKey Entity signing public key.
     *
     * @return boolean specifying if the verification was successful.
     */
    public boolean verifyJwt(String jwt, String publicKey) {

        if (debug) {
            log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: verify JWT");
        }

        jwt = jwt.replaceAll("\"", "");

        try {
            boolean result = citizenCrypto.verifyCitizenJwt(jwt, publicKey);
            log(Constant.CITIZEN_CRYPTO_SUCCESS, "INFO: verified JWT");
            return result;
        } catch (CryptoException e) {
            log(Constant.CITIZEN_CRYPTO_ERROR, getStackTrace(e));
            return false;
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Set details of a Person. These calls are intended to be used for setting up test accounts.
    /////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Set the name of a Citizen user.
     *
     * This call requires a user apiKey to be set. It can be set with the setApiKey() method.
     *
     * @param personId Person ID of the user. This may be obtained from the {@link User} object
     * @param firstName First name
     * @param middleName Middle name
     * @param lastName Last name
     * @param title Title
     *
     * @return Optional {@link Person}
     */
    public Optional<Person> setPersonName(String personId,
                                          String firstName,
                                          String middleName,
                                          String lastName,
                                          String title) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Setting person name: (" +
                     "personId: " + personId + ", " +
                     "firstName: " + firstName + ", " +
                     "middleName: " + middleName + ", " +
                     "lastName: " + lastName + ", " +
                     "title: " + title + ")");
        }

        Name name = new Name();
        name.setFirstName(firstName);
        name.setMiddleName(middleName);
        name.setLastName(lastName);
        name.setTitle(title);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            Person person = restClient.post(Constant.CITIZEN_PERSON_RESOURCE + "/" + personId + "/name", name, Person.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Added name for person: " + personId);
            return Optional.of(person);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Set the gender of a Citizen user.
     *
     * This call requires a user apiKey to be set. It can be set with the setApiKey() method.
     *
     * @param personId Person ID of the user. This may be obtained from the {@link User} object
     * @param gender {@link GenderType}
     *
     * @return Optional {@link Person}
     */
    public Optional<Person> setPersonGender(String personId, GenderType gender) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Setting person gender: (" +
                     "personId: " + personId + ", " +
                     "gender: " + gender.toString() + ")");
        }

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        String quotedGender = "\"" + gender.toString() + "\"";

        try {
            Person person = restClient.put(Constant.CITIZEN_PERSON_RESOURCE + "/" + personId + "/gender", quotedGender, Person.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Set person gender: " + personId);
            return Optional.of(person);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Set the date of birth of a Citizen user.
     *
     * This call requires a user apiKey to be set. It can be set with the setApiKey() method.
     *
     * @param personId Person ID of the user. This may be obtained from the {@link User} object
     * @param dateOfBirth {@link DateTime}
     *
     * @return Optional {@link Person}
     */
    public Optional<Person> setPersonDateOfBirth(String personId, DateTime dateOfBirth) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Setting person date of birth: (" +
                     "personId: " + personId + ", " +
                     "dateOfBirth: " + dateOfBirth.toString() + ")");
        }

        Person person = new Person();
        person.setId(personId);
        person.setDateOfBirth(dateOfBirth);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            person = restClient.put(Constant.CITIZEN_PERSON_RESOURCE + "/" + personId + "/dateOfBirth", person, Person.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Set date of birth for person: " + personId);
            return Optional.of(person);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Set a Citizen user's nationality.
     *
     * This call requires a user apiKey to be set. It can be set with the setApiKey() method.
     *
     * @param personId Person ID of the user. This may be obtained from the {@link User} object
     * @param countryName {@link CountryName}
     *
     * @return Optional {@link Person}
     */
    public Optional<Person> setNationality(String personId, CountryName countryName) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Setting person nationality: (" +
                     "personId: " + personId + ", " +
                     "countryName: " + countryName.toString() + ")");
        }

        Person person = new Person();
        person.setId(personId);
        person.setCountryNationality(countryName);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            person = restClient.put(Constant.CITIZEN_PERSON_RESOURCE + "/" + personId + "/nationality", person, Person.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Set date of birth for person: " + personId);
            return Optional.of(person);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     *  Set a Citizen user's place of birth.
     *
     *  This call requires a user apiKey to be set. It can be set with the setApiKey() method.
     *
     * @param personId Person ID of the user. This may be obtained from the {@link User} object
     * @param placeOfBirth place of birth.
     *
     * @return Optional {@link Person}
     */
    public Optional<Person> setPersonPlaceOfBirth(String personId, String placeOfBirth) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Setting person place of birth: (" +
                     "personId: " + personId + ", " +
                     "placeOfBirth: " + placeOfBirth.toString() + ")");
        }

        Person person = new Person();
        person.setId(personId);
        person.setPlaceOfBirth(placeOfBirth);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            person = restClient.put(Constant.CITIZEN_PERSON_RESOURCE + "/" + personId + "/placeOfBirth", person, Person.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Set place of birth for person: " + personId);
            return Optional.of(person);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(), getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    /**
     * Set a Citizen user's address.
     *
     * This call requires a user apiKey to be set. It can be set with the setApiKey() method.
     *
     * @param personId Person ID of the user. This may be obtained from the {@link User} object
     * @param addressLine1 Address line 1
     * @param addressLine2 Address line 2
     * @param addressLine3 Address line 3
     * @param city City
     * @param addressCountryName Country
     * @param postcode Post code
     * @param addressType Address type (home, office etc)
     *
     * @return Optional {@link Address}
     */
    public Optional<Address> setPersonAddress(String personId,
                                              String addressLine1,
                                              String addressLine2,
                                              String addressLine3,
                                              String city,
                                              CountryName addressCountryName,
                                              String postcode,
                                              AddressType addressType) {

        if (debug) {
             log(Constant.CITIZEN_GENERAL_INFO, "DEBUG: Setting person place of birth: (" +
                     "personId: " + personId + ", " +
                     "addressLine1: " + addressLine1 + ", " +
                     "addressLine2: " + addressLine2 + ", " +
                     "addressLine3: " + addressLine3 + ", " +
                     "city: " + city + ", " +
                     "countryName: " + addressCountryName.toString() + ", " +
                     "postcode: " + personId + ", " +
                     "addressType: " + addressType.toString() + ")");
        }

        Address address = new Address();
        address.setAddressLine1(addressLine1);
        address.setAddressLine2(addressLine2);
        address.setAddressLine3(addressLine3);
        address.setCity(city);
        address.setCountryName(addressCountryName);
        address.setPostCode(postcode);
        address.setAddressType(addressType);

        if (apiKey != null) {
            restClient.clearApiHeaders();
            restClient.setApiKey(apiKey);
        } else {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, "ERROR: API key not set");
            return Optional.empty();
        }

        try {
            address = restClient.post(Constant.CITIZEN_PERSON_RESOURCE + "/" + personId + "/address", address, Address.class);
            log(Constant.CITIZEN_REST_SUCCESS, "INFO: Set address of birth for person: " + personId);
            return Optional.of(address);
        } catch (HttpStatusCodeException e) {
            log(e.getStatusCode().value(),  getStackTrace(e));
        } catch (RestException e) {
            log(Constant.CITIZEN_REST_GENERAL_ERROR, getStackTrace(e));
        }

        return Optional.empty();
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public boolean getDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    // Change the API server.

    public void setApiHost(String apiHost) {
        this.apiHost = apiHost;
    }

    public void setApiPort(int apiPort) {
        this.apiPort = apiPort;
    }

    public void setApiSecure(boolean apiSecure) {
        this.apiSecure = apiSecure;
    }

    public void disableTlsCertCheck() {
        this.restClient.disableTlsCertCheck();
    }

    public void updateRestParameters() {
        restClient.setApiHost(apiHost);
        restClient.setApiPort(apiPort);
        restClient.setApiSecure(apiSecure);
    }

    public static String getStackTrace(final Throwable throwable) {
       final StringWriter sw = new StringWriter();
       final PrintWriter pw = new PrintWriter(sw, true);
       throwable.printStackTrace(pw);
       return sw.getBuffer().toString();
    }

    // Call backs.

    public void webStompLoggingCallback(int code, String logMessage) {
        log(code, logMessage);
    }
}
