package is.citizen.sdk.examples;

import is.citizen.sdk.crypto.KeyHolder;
import is.citizen.sdk.enums.*;
import is.citizen.sdk.resource.*;

import is.citizen.sdk.api.CitizenApi;
import is.citizen.sdk.util.Constant;
import org.apache.commons.cli.*;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

public class Examples {

    public static void runExamples() {

        String userApiKey = null;
        String userSecret = null;

        //
        // Initialise the Citizen api.
        //

        CitizenApi citizenApi = new CitizenApi();
        citizenApi.setApiHost("localhost");
        citizenApi.setApiPort(8443);
        citizenApi.setApiSecure(false);
        citizenApi.updateRestParameters();

        citizenApi.registerLoggingCallback((status, message) -> {
            System.out.println("LOG: status: " + status + ", message: " + message);
        });

        //
        // Generate a key pair for authentication.
        //

        Optional<KeyHolder> authKeyHolder = citizenApi.generateAuthKeyPair("secret");

        String authPublicKey = authKeyHolder.get().getPublicKey();
        String authPrivateKey = authKeyHolder.get().getPrivateKey();

        System.out.println("********************************");
        System.out.println("Generated key pair:");
        System.out.println("Public key: " + authPublicKey);
        System.out.println("Private key: " + authPrivateKey);
        System.out.println("********************************\n");

        //
        // Convert the key pair to Java PublicKey and PrivateKey objects.
        //

        PublicKey javaAuthPublicKey = citizenApi.convertAuthPublicKeyStringToJava(authPublicKey).get();
        PrivateKey javaAuthPrivateKey = citizenApi.convertAuthPrivateKeyStringToJava(authPrivateKey, "secret").get();

        System.out.println("********************************");
        System.out.println("Converted auth key pair to Java PublicKey and PrivateKey objects");
        System.out.println("********************************\n");

        //
        // Generate a key pair for encryption.
        //

        Optional<KeyHolder> cryptoKeyHolder = citizenApi.generateAuthKeyPair("secret");

        String cryptoPublicKey = authKeyHolder.get().getPublicKey();
        String cryptoPrivateKey = authKeyHolder.get().getPrivateKey();

        System.out.println("********************************");
        System.out.println("Generated key pair:");
        System.out.println("Public key: " + authPublicKey);
        System.out.println("Private key: " + authPrivateKey);
        System.out.println("********************************\n");

        //
        // Convert the key pair to Java PublicKey and PrivateKey objects.
        //

        PublicKey javaCryptoPublicKey = citizenApi.convertAuthPublicKeyStringToJava(cryptoPublicKey).get();
        PrivateKey javaCryptoPrivateKey = citizenApi.convertAuthPrivateKeyStringToJava(cryptoPrivateKey, "secret").get();

        System.out.println("********************************");
        System.out.println("Converted crypto key pair to Java PublicKey and PrivateKey objects");
        System.out.println("********************************\n");

        //
        // Create a new test user.
        //

        String username = UUID.randomUUID().toString();
        String userEmail = username + "@test.com";
        String passPhrase = "Test12";

        User user = citizenApi.createUser(username, userEmail, passPhrase, authPublicKey).get();

        System.out.println("********************************");
        System.out.println("Created user: ");
        System.out.println("Username: " + user.getUsername());
        System.out.println("API key: " + user.getApiKey());
        System.out.println("********************************\n");

        userApiKey = user.getApiKey();
        userSecret = user.getMnemonicCode();

        citizenApi.setApiKey(userApiKey);
        citizenApi.setSecret(userSecret);

        //
        // Add the user's auth public key.
        //

        citizenApi.registerUserAuthPublicKey(user.getId(), authPublicKey);

        System.out.println("********************************");
        System.out.println("Registered auth public key for user");
        System.out.println("********************************\n");

        //
        // Add a few details for the user.
        //

        citizenApi.setPersonName(user.getPersonId(), "John", "Paul", "Doe", NameTitle.MR.toString());

        citizenApi.setPersonAddress(user.getPersonId(),
                                    "1 Main Street",
                                    "Main Avenue",
                                    "Mainville",
                                    "London",
                                    CountryName.GB,
                                    "111 ABC",
                                    AddressType.HOME);

        DateTimeFormatter formatter = DateTimeFormat.forPattern("dd/MM/yyyy HH:mm:ss");
        DateTime dateOfBirth = formatter.parseDateTime("01/01/1980 23:00:00");

        citizenApi.setPersonDateOfBirth(user.getPersonId(), dateOfBirth);

        System.out.println("********************************");
        System.out.println("Add user personal details");
        System.out.println("********************************\n");

        //
        // Log in with signature.
        //

        user = citizenApi.loginWithSignature(userEmail, authPrivateKey, "secret").get();

        System.out.println("********************************");
        System.out.println("Log in with signature: ");
        System.out.println("API key: " + user.getApiKey());
        System.out.println("********************************\n");

        //
        // Create a few tokens.
        //

        int access = 0;
        access = AccessType.add(access, AccessType.NAME);
        access = AccessType.add(access, AccessType.DOB);
        TokenDurationType durationType = TokenDurationType.MONTH;
        int duration = 6;

        Token token_1 = citizenApi.createToken(userEmail,
                                               access,
                                               durationType,
                                               duration).get();

        System.out.println("********************************");
        System.out.println("Created token: ");
        System.out.println("Token ID: " + token_1.getId());
        System.out.println("********************************\n");

        access = AccessType.add(0, AccessType.NAME);
        access = AccessType.add(access, AccessType.ADDRESS);
        durationType = TokenDurationType.WEEK;
        duration = 2;

        Token token_2 = citizenApi.createToken(userEmail,
                                               access,
                                               durationType,
                                               duration).get();

        System.out.println("********************************");
        System.out.println("Created token: ");
        System.out.println("Token ID: " + token_2.getId());
        System.out.println("********************************\n");

        access = AccessType.add(0, AccessType.NAME);
        access = AccessType.add(access, AccessType.TOKEN_SIGNATURE);
        durationType = TokenDurationType.DAY;
        duration = 1;

        citizenApi.setApiKey(userApiKey);
        citizenApi.setSecret(userSecret);

        Token token_3 = citizenApi.createToken(userEmail,
                                               access,
                                               durationType,
                                               duration).get();

        System.out.println("********************************");
        System.out.println("Created token: ");
        System.out.println("Token ID: " + token_3.getId());
        System.out.println("********************************\n");

        //
        // Get tokens belonging to the user.
        //

        TokenWrapper userTokens = citizenApi.getUserTokens().get();

        System.out.println("********************************");
        System.out.println("Fetched user tokens: ");
        for (Token token : userTokens.getTokens()) {
            System.out.println("Token ID: " + token.getId());
        }
        System.out.println("********************************\n");

        //
        // Get tokens belonging to the requester.
        //

        TokenWrapper requesterTokens = citizenApi.getRequesterTokens().get();

        System.out.println("********************************");
        System.out.println("Fetched requester tokens: ");
        for (Token token : userTokens.getTokens()) {
            System.out.println("Token ID: " + token.getId());
        }
        System.out.println("********************************\n");

        //
        // Get an individual token.
        //

        String userTokenId = userTokens.getTokens().get(0).getId();

        Token token = citizenApi.getToken(userTokenId).get();

        System.out.println("********************************");
        System.out.println("Fetched individual token: ");
        System.out.println("Token ID: " + token.getId());
        System.out.println("********************************");

        //
        // Grant a token.
        //

        String grantedTokenId = userTokens.getTokens().get(0).getId();

        token = citizenApi.grantToken(token).get();

        System.out.println("********************************");
        System.out.println("Grant token:");
        System.out.println("Token ID: " + token.getId());
        System.out.println("********************************");

        //
        // Decline a token.
        //

        String declinedTokenId = userTokens.getTokens().get(1).getId();

        token = citizenApi.declineToken(declinedTokenId).get();

        System.out.println("********************************");
        System.out.println("Decline token:");
        System.out.println("Token ID: " + token.getId());
        System.out.println("********************************");

        //
        // Delete a token.
        //

        citizenApi.deleteToken(token.getId());

        System.out.println("********************************");
        System.out.println("Delete token:");
        System.out.println("********************************");

        //
        // Sign a token.
        //

        Token signedToken = citizenApi.signToken(token_3, authPrivateKey, "secret").get();

        //
        // Verify the signed token.
        //

        boolean tokenVerified = citizenApi.verifyTokenSignature(signedToken);

        System.out.println("********************************");
        System.out.println("Sign and verify token:");
        System.out.println("verified: " + tokenVerified);
        System.out.println("********************************");

        //
        // Create an entity.
        //

        // First create the admin account for the entity.

        String entityUsername = UUID.randomUUID().toString() + "@test.com";
        String entityEmail = entityUsername + "@test.com";
        String entityPassword = "Test1234";
        String entityPassphrase = "Test12";
        String entityAdminEmail = UUID.randomUUID().toString() + "@test.com";
        String entityAdminPassword = "Test1234";

        Entity entity = citizenApi.createEntity(entityUsername,
                                                entityEmail,
                                                entityPassword,
                                                entityPassphrase,
                                                "Megacorp Holdings Ltd",
                                                entityAdminEmail,
                                                entityAdminPassword,
                                                "Megacorp",
                                                "12345678",
                                                "1 Main Road",
                                                "Main Avenue",
                                                "Mainville",
                                                "London",
                                                CountryName.GB,
                                                "123 ABC",
                                                "12345678",
                                                CountryCode.GB).get();

        System.out.println("********************************");
        System.out.println("Create entity:");
        System.out.println("entity ID: " + entity.toString());
        System.out.println("********************************");

        //
        // Log in with the entity admin user to get its API key.
        //

        User entityAdminUser = citizenApi.loginWithUsernameAndPassword(entityAdminEmail, entityPassword).get();

        System.out.println("********************************");
        System.out.println("Log in as entity admin:");
        System.out.println("API key: " + entityAdminUser.getApiKey());
        System.out.println("********************************");

        String entityAdminApiKey = entityAdminUser.getApiKey();

        //
        // Get the entity admin user's secret.
        //

        String entityAdminSecret = citizenApi.getUserSecret(entityAdminEmail, entityPassphrase).get();

        System.out.println("********************************");
        System.out.println("Get entity admin secret:");
        System.out.println("Secret: " + entityAdminSecret);
        System.out.println("********************************");

        //
        // Get an entity.
        //

        String entityId = entity.getId();
        String entityApiKey = entity.getApi();
        String entitySecret = entity.getMnemonicCode();

        citizenApi.setApiKey(entityAdminApiKey);
        citizenApi.setSecret(entityAdminSecret);

        entity = citizenApi.getEntity(entityId).get();

        System.out.println("********************************");
        System.out.println("Get entity:");
        System.out.println("entity ID: " + entity.getId());
        System.out.println("********************************");

        //
        // Register an entity web hook.
        //

        int webHookEventType = 0;
        EventType.add(webHookEventType, EventType.TOKEN_GRANTED_BY_USER);
        EventType.add(webHookEventType, EventType.TOKEN_DECLINED_BY_USER);

        entity = citizenApi.addEntityWebHook(entityId, webHookEventType, "http://www.test.com/citizenWebHook").get();

        System.out.println("********************************");
        System.out.println("Register entity web hook:");
        System.out.println("Web hooks: " + entity.getWebHooks().toString());
        System.out.println("********************************");

        //
        // Remove the entity web hook.
        //

        entity = citizenApi.removeEntityWebHook(entityId, webHookEventType, "http://www.test.com/citizenWebHook").get();

        System.out.println("********************************");
        System.out.println("Remove entity web hook:");
        System.out.println("Web hooks: " + entity.getWebHooks().toString());
        System.out.println("********************************");

        //
        // Create a couple users and add them to the entity.
        //

        String entityUsername1 = UUID.randomUUID().toString();
        String entityUserEmail1 = entityUsername1 + "@test.com";
        String entityUserPassPhrase1 = "Test12";
        String entityUserEntityEmail1 = UUID.randomUUID().toString() + "@test.com";

        User entityUser1 = citizenApi.createUser(entityUsername1, entityUserEmail1, entityUserPassPhrase1, null).get();

        String entityUsername2 = UUID.randomUUID().toString();
        String entityUserEmail2 = entityUsername2 + "@test.com";
        String entityUserPassPhrase2 = "Test12";
        String entityUserEntityEmail2 = UUID.randomUUID().toString() + "@test.com";

        User entityUser2 = citizenApi.createUser(entityUsername2, entityUserEmail2, entityUserPassPhrase2, null).get();

        // First we add the entity email to the user.

        citizenApi.setApiKey(entityUser1.getApiKey());
        entityUser1 = citizenApi.setUserEntity(entityUser1.getId(), entityUserEntityEmail1).get();
        citizenApi.setApiKey(entityUser2.getApiKey());
        entityUser2 = citizenApi.setUserEntity(entityUser2.getId(), entityUserEntityEmail2).get();

        // Then we add all users with this entity email to the entity.

        citizenApi.setApiKey(entityAdminApiKey);
        citizenApi.setSecret(entityAdminSecret);

        entity = citizenApi.addEntityUser(entityId, entityUserEntityEmail1).get();
        entity = citizenApi.addEntityUser(entityId, entityUserEntityEmail2).get();

        System.out.println("********************************");
        System.out.println("Add entity user.");
        System.out.println("********************************");

        //
        // Get entity users.
        //

        UserWrapper entityUsers = citizenApi.getEntityUsers(entityId).get();

        System.out.println("********************************");
        System.out.println("Get entity users.");
        System.out.println(entityUsers.toString());
        System.out.println("********************************");

        //
        // Update an entity user to an admin.
        //

        entity = citizenApi.updateEntityAdmin(entityId, entityUser1.getPersonId(), true).get();

        System.out.println("********************************");
        System.out.println("Update entity admin.");
        System.out.println("********************************");

        //
        // Delete a user.
        //

        entity = citizenApi.removeEntityUser(entityId, entityUser1.getPersonId()).get();

        System.out.println("********************************");
        System.out.println("Delete entity user.");
        System.out.println("********************************");

        //
        // Regenerate the entity's signing key.
        //

        entity = citizenApi.regenerateEntitySigningKey(entityId).get();

        System.out.println("********************************");
        System.out.println("Regenerate entity signing key:");
        System.out.println("Public signing key: " + entity.getSigningPublicKey());
        System.out.println("********************************");

        //
        // Register a crypto public key for the entity.
        //

        // First generate the key pair.

        Optional<KeyHolder> signingKeyHolder = citizenApi.generateCryptoKeyPair("secret");

        String entityCryptoPublicKey = signingKeyHolder.get().getPublicKey();
        String entityCryptoPrivateKey = signingKeyHolder.get().getPrivateKey();

        citizenApi.registerEntityCryptoPublicKey(entityId, entityCryptoPublicKey);

        System.out.println("********************************");
        System.out.println("Register entity crypto public key:");
        System.out.println("Public key: " + entityCryptoPublicKey);
        System.out.println("********************************");

        //
        // Register an entity data agreement.
        //

        entity = citizenApi.registerDataAgreement(entityId,
                                                  6,
                                                  TokenDurationType.MONTH,
                                                  "Basic Data Agreement",
                                                  "Marketing",
                                                  Arrays.asList("HyperMegaCorp", "AddStream", "ClickJungle")).get();

        System.out.println("********************************");
        System.out.println("Register data agreement:");
        System.out.println("********************************");

        //
        // Register an entity grey user.
        //

        String greyUserEmail = UUID.randomUUID().toString() + "@test.com";
        String entityPublicApiKey = entity.getPublicApiKey();

        citizenApi.setApiKey(entityPublicApiKey);

        GreyUser greyUser = citizenApi.registerEntityUser(
                greyUserEmail,                 // User email.
                "John",                        // First name.
                "Paul",                        // Middle name.
                "Doe",                         // Last name.
                NameTitle.MR.toString(),       // Title.
                GenderType.MALE.toString(),    // Gender.
                dateOfBirth,                   // Date of birth.
                "1 Main Street",               // Address line 1.
                "Main Road",                   // Address line 2.
                "Main Avenue",                 // Address line 3.
                "London",                      // City.
                CountryName.GB,                // Country.
                "123 ABC",                     // Post code.
                AddressType.HOME,              // Address type.
                "12345678",                    // Phone number.
                CountryCode.GB,                // Phone country.
                PhoneType.HOME).get();         // Phone type.

        System.out.println("********************************");
        System.out.println("Register entity grey user:");
        System.out.println("Person Id: " + greyUser.getPersonId());
        System.out.println("Email: " + greyUser.getPrimaryEmail());
        System.out.println("********************************");

        //
        // Check if a user exists.
        //

        citizenApi.setApiKey(entityApiKey);
        citizenApi.setSecret(entitySecret);

        UserCheck userCheck = citizenApi.checkEntityUserExists(entityUserEmail2).get();

        System.out.println("********************************");
        System.out.println("Check if an entity user exists:");
        System.out.println("Result: " + userCheck.getUserExists());
        System.out.println("********************************");

        //
        // Get JWT via web socket.
        //

        // First send the token.

        String citizenNonce = citizenApi.sendJwtLoginTokenToUser(entityId, userEmail, "12345678").get();

        // Next wait for the JWT to be delivered via web socket after the user has approved it.

        String signingPublicKey = entity.getSigningPublicKey();

        citizenApi.setupStompClientAndReceiveJwt(citizenNonce, jwt -> {
            boolean verified = citizenApi.verifyJwt(jwt, signingPublicKey);

            System.out.println("********************************");
            System.out.println("Entity login with JWT:");
            System.out.println("JWT valid: " + verified);
            System.out.println("********************************");
        });

        // Finally, simulate the user approving the token for demo purposes.

        citizenApi.setApiKey(userApiKey);
        citizenApi.setSecret(userSecret);

        String webTokenId = null;
        userTokens = citizenApi.getUserTokens().get();
        for (Token userToken : userTokens.getTokens()) {
            if (userToken.getTokenStatus() == TokenStatus.WEB_ACCESS_REQUEST) {
                webTokenId = userToken.getId();
            }
        }

        Token webToken = citizenApi.getToken(webTokenId).get();

        webToken = citizenApi.grantToken(webToken).get();
    }

    public static void generateAuthKeyPair(String password) {
        CitizenApi citizenApi = new CitizenApi();
        citizenApi.registerLoggingCallback((status, message) -> {
            if (status == Constant.CITIZEN_CRYPTO_ERROR) {
                System.out.println("Log: status: " + status + ", message: " + message);
            }
        });

        Optional<KeyHolder> keyHolder = citizenApi.generateAuthKeyPair(password);

        String publicKey = keyHolder.get().getPublicKey();
        String privateKey = keyHolder.get().getPrivateKey();

        System.out.println("\nAuth Public Key:");
        System.out.println(publicKey);
        System.out.println("");
        System.out.println("Auth Private Key:");
        System.out.println(privateKey);
    }

    public static void generateCryptoKeyPair(String password) {
        CitizenApi citizenApi = new CitizenApi();
        citizenApi.registerLoggingCallback((status, message) -> {
            if (status == Constant.CITIZEN_CRYPTO_ERROR) {
                System.out.println("Log: status: " + status + ", message: " + message);
            }
        });

        Optional<KeyHolder> keyHolder = citizenApi.generateCryptoKeyPair(password);

        String publicKey = keyHolder.get().getPublicKey();
        String privateKey = keyHolder.get().getPrivateKey();

        System.out.println("\nCrypto Public Key:");
        System.out.println(publicKey);
        System.out.println("");
        System.out.println("Crypto Private Key:");
        System.out.println(privateKey);
    }

    public static void main(String[] args) {

        Options options = new Options();

        Option authKey = new Option("a", "authKey", true, "auth key secret");
        options.addOption(authKey);
        Option cryptoKey = new Option("a", "cryptoKey", true, "crypto key secret");
        options.addOption(cryptoKey);
        Option runExamples = new Option("runExamples", "run examples");
        options.addOption(runExamples);

        CommandLineParser parser = new GnuParser();
        try {
            CommandLine line = parser.parse( options, args );
            if (line.hasOption("authKey")) {
                String secret = line.getOptionValue("authKey");
                if (secret != null) {
                    generateAuthKeyPair(secret);
                } else {
                    System.err.println("Secret for auth key must be given");
                }
            } else if (line.hasOption("cryptoKey")) {
                String secret = line.getOptionValue("cryptoKey");
                if (secret != null) {
                    generateCryptoKeyPair(secret);
                } else {
                    System.err.println("Secret for crypto key must be given");
                }
            } else if (line.hasOption("runExamples")) {
                Examples.runExamples();
            } else {
                System.err.println("Incorrect usage.");
            }
        } catch(ParseException e) {
            System.err.println("Arugment parsing failed: " + e.getMessage());
        }
    }
}
