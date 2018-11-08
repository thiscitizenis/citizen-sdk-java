## Java SDK for the Citizen secure login and data exchange service

More about the Citizen Service can be found here:

  https://www.citizen.is/

and here:

  https://developers.citizen.is/

The project has examples of the following operations, which can be found in Examples.java

  - Generate Authentication and Cryptographic key pairs.
  - Create a user.
  - Register a user's authentication public key.
  - Add user details.
  - Log in as a user using a signed identifier.
  - Create a token.
  - Get a token.
  - Get user tokens.
  - Get requester tokens.
  - Grant a token.
  - Decline a token.
  - Delete a token.
  - Sign a token.
  - Verify a signed token.
  - Create a third party entity.
  - Log in as the entity admin user.
  - Get a third party entity.
  - Register a third party entity web hook.
  - Remove a third party entity web hook.
  - Add a user to a third party entity.
  - Get all third party entity users.
  - Remove a user from a third party entity.
  - Regenerate a third party entity's signing key.
  - Register a encryption/decryption public key for a third party entity.
  - Register a third party entity data agreement.
  - Register a third party entity grey user.
  - Check if a third party entity user exists.

The project can be built with the command:

```
mvn clean install
```

The examples can be run with the command:

```
java -jar target/sdk-1.0-SNAPSHOT-jar-with-dependencies.jar -runExamples
```

Authentication and cryptographic key pairs can also be generated, but running the following commands:


```
java -jar target/sdk-1.0-SNAPSHOT-jar-with-dependencies.jar -authKey <keyPassword>
```

```
java -jar target/sdk-1.0-SNAPSHOT-jar-with-dependencies.jar -cryptoKey <keyPassword>
```

### Using the Citizen Java SDK

The Java SDK allows a third-party entity to integrate their service with Citizen. It has functionality for handling tokens, configuration of authentication and encryption keys, and endpoints and login management. It can also be used to set up test accounts which can be used to validate configuration. Sample code of these operations is contained in Examples.java.

### Building and installing the SDK

The SDK can be built with the following command:

```
  mvn clean install
```

### Initialising the SDK

The SDK is initialised by giving the connection details of the Citizen Service.

```
  CitizenApi citizenApi = new CitizenApi();
  citizenApi.useDevelopmentApi();
```

A logging callback may also be registered. This returns a status code and log message. The code below registers an anonymous function:

```
  citizenApi.registerLoggingCallback((status, message) -> {
      LOGGER.info("status: " + status + ", message: " + message);
  });
```

### Generating Key Pairs

The Citizen Service uses public/private key pairs for encryption and for authentication. RSA 2048 bit keys are used for encryption. Authentication uses ECDSA signatures with EC secp256r1 (aka P-256 aka prime256v1) keys. The two types of keys are referred to as 'crypto' and 'auth' keys throughout the SDK.

The SDK can be used to generate and manage keys for both encryption and authentication. When a key pair is generated, it is returned in a KeyHolder object, which contains the public and private keys encoded in Base 64. The public key is in Base 64 encoded DER format. The private key is symmetrically encrypted using a password. Having the keys encoded as Base 64 strings is convenient for storage.

A key pair for encryption and decryption may be generated as follows:

```
  Optional<KeyHolder> keyHolder = citizenApi.generateCryptoKeyPair("password");
```

The argument is the password with which to encrypt the private key.

A key pair for authentication can be generated as follows:

```
  Optional<KeyHolder> keyHolder = citizenApi.generateAuthKeyPair("password");
```

The keys (either for encryption/decryption or authentication) can be accessed as follows:

```
  String publicKey = keyHolder.get().getPublicKey();
  String privateKey = keyHolder.get().getPrivateKey();
```

They can be converted to Java `PublicKey` and `PrivateKey` objects with the calls:

```
  PublicKey authPublicKey = citizenApi.convertAuthPublicKey(String publicKey)
  PrivateKey authPrivateKey = citizenApi.convertAuthPrivateKey(String privateKey)
  PublicKey cryptoPublicKey = citizenApi.convertCryptoPublicKey(String publicKey)
  PrivateKey cryptoPrivateKey = citizenApi.convertCryptoPrivateKey(String privateKey)
```

### User Operations

Users may be added to the Citizen Service with the SDK. The users created through this call are identical to a user signing up through the Citizen website or app. This functionality is for use setting up test accounts - in general users will sign up from the Citizen website or app. A user can be set up as follows:

```
  User user = citizenApi.createUser(userName, userEmail, passPhrase, authPublicKey).get();
```

The `userName` and `userEmail` arguments are self-explanatory. The `passPhrase` argument is used by the Citizen Service to algorithmically generate a password for the user's private key. The `authPublicKey` argument contains a Base64 encoded EC public key of the type generated by `generateAuthKeyPair()` covered above. This field is not necessary and may be set to null, if it is set then the user can log in by signing a nonce with the corresponding EC private key.

Upon user creation, a `User` object is returned. 

Fields of interest in this object are:

  * `apiKey`        - used to access the Citizen REST API
  * `mnemonicCode`  - password to unlock the user's private key on the Citizen Sevice
  * `personId`      - used for calls to update a user's personal data

Personal data such as name, address and date of birth can be set with the following calls:

```
  citizenApi.setPersonName(personId, firstName, middleName, lastName, title);

  citizenApi.setPersonAddress(personId, addressLine1, addressLine2, addressLine3, addressLine4, city, country, postCode, addressType);

  citizenApi.setPersonDateOfBirth(personId, dateOfBirth);
```

The arguments to these functions are mostly self-explanatory. Examples of their user may be found in Examples.java.

If the user has an authentication public key registered (covered above), a login can be done for the user with the following call:

```
  citizenApi.loginWithSignature(userEmail, authPrivateKey, keyPassword);
```

Upon logging in a User object is returned. The `apiKey` and `mnemonicCode` fields in the User object may be used to send and receive tokens, which are covered in the next section. They can be set in the SDK with the following calls:

```
  citizenApi.setApiKey(apiKey);
  citizenApi.setSecret(keyPassword);
```

## Token Operations

Tokens encapsulate the data relationship between businesses and users. A business may request data from a user, such as their name and date of birth. Upon doing so, a token is sent to the user requesting this data. If they grant the token, their name and date of birth is decrypted on the Citizen Service with their private key, and encrypted with the public key of the business. The business is then notifified that the user has granted the token and it may now access the encrypted data with its private key. Time limits can be set on the data access, and it is also possible to request that a user signs a token using their device fingerprint.

The first step of the process is that a business creates a token, which may be done with code like the following through the SDK:

```
  int access = 0;
  access = AccessType.add(access, AccessType.NAME);
  access = AccessType.add(access, AccessType.DOB);
  TokenDurationType durationType = TokenDurationType.MONTH;
  int duration = 6;

  Token token_1 = citizenApi.createToken(userEmail,
                                         access,
                                         durationType,
                                         duration).get();
```

The data the business wants access to is passed as a bit mask. In the example above the business is requesting the user's name and date of birth. It is requesting this data for six months.

If the user has the Citizen app, they will be notifified that the business has requested this data from them. For testing and demonstration purposes, we can retrieve and grant the token through the SDK.

Fetching tokens for the user may be done with the following call:

```
  TokenWrapper wrapper = citizenApi.getUserTokens().get();
```

The business may get all tokens it has sent with the following call:

```
  TokenWrapper wrapper = citizenApi.getRequesterTokens().get();
```

Tokens for both of these calls are returned in a `TokenWrapper` object. This may be itereated through as follows:

```
  for (Token token : tokenWrapper.getTokens()) {
    System.out.println("Token ID: " + token.getId());
  }
```

This will print the ID of each token in the TokenWrapper object. A token sent to a user may be granted as follows:

```
  Token token = citizenApi.grantToken(token).get();
```

Once granted, the business that sent the token will be able to access the data it requested. It may fetch the token with the call:

```
  Token token = citizenApi.getToken(tokenId).get();
```

These calls need the API key and private key password for the user or business to be set, which are set with:

```
  citizenApi.setApiKey(apiKey);
  citizenApi.setSecret(keyPassword);
```
  
Further examples of creating, granting, declining, deleting and signing tokens can be found in Examples.java.

### Entities

A business wishing to request data from Citizen users must first register with the Citizen Service. This would usually be done through the website, but it is also possible to do this through the SDK, which may be useful for automated tests. The business registers with Citizen as an 'Entity'. This can be done through the following call:

```
  Entity entity = citizenApi.createEntity(entityUsername,
                                          entityEmail,
                                          entityPassword,
                                          entityPassphrase,
                                          entityName,
                                          entityAdminEmail,
                                          entityAdminPassword,
                                          entityTradingName,
                                          entityCompanyNumber,
                                          entityAddressLine1,
                                          entityAddressLine2,
                                          entityAddressLine3,
                                          entityAddressCity,
                                          entityAddressCountryName,
                                          entityAddressPostCode,
                                          entityPhoneNumber,
                                          entityPhoneCountryCode).get();
```

The field names should be self-explanatory, but further details can be found in the JavaDoc for the call. The entity's admin account is used for operations such as registering web hooks, updating encryption keys and adding users to an entity. Calls with the admin account are made using its API key, which can be obtained by logging in with the account credentials:

```
  User entityAdminUser = citizenApi.loginWithUsernameAndPassword(entityAdminEmail, entityPassword).get();
```

A `User` object is returned object is returned upon successful login. Its API key may be accessed as follows:

```
  String entityAdminApiKey = entityAdminUser.getApiKey();
```

Web hooks allow a third-party server to be notified and to process events relating to Citizen users they have issued tokens to. When such an event occurs, a POST request with JSON like the following is sent to the third-party server:

```
  {
    EventType: 8388608,
    Token: { Serialised Token object }
  }
```

The first item in the JSON object is an integer that functions as a bitmask, allowing multiple event types to be sent to the one endpoint. The second is the object for which the event relates. In the example above, the event type is when a token has been granted by a user. The object is the serialised token that was granted. 

To be notified, say, when a user has added requested documents that were requested in a token, such as a passport and driving license, the request sent via web hook would look like the following:

```
  {
    EventType: 4096,
    [
      Serialised passport document,
      Serialised driving license document
    ]
  }
```

A web hook may be added as follows:

```
  int webHookEventType = 0;
  EventType.add(webHookEventType, EventType.TOKEN_GRANTED_BY_USER);
  EventType.add(webHookEventType, EventType.TOKEN_DECLINED_BY_USER);

  Entity entity = citizenApi.addEntityWebHook(entityId, webHookEventType, "http://www.test.com/citizenWebHook").get();
```

It may be removed as follows:

```
  Entity entity = citizenApi.removeEntityWebHook(entityId, webHookEventType, "http://www.test.com/citizenWebHook").get();
```

Citizen users may be added to an entity. This relationship is intended if the user is, say, an employee of the business that manages the entity. An email address linking the user to the entity is added first:

```
  String entityUserEmail = "john.doe@megacorp.com";

  User entityUser = citizenApi.setUserEntity(entityUser1.getId(), entityUserEntityEmail1).get();
```
  
This is then linked to the entity by the email address:

```
  Entity entity = citizenApi.addEntityUser(entityId, entityUserEmail).get();
```

A list of users linked to the entity in this way may be obtained with:

```
  UserWrapper entityUsers = citizenApi.getEntityUsers(entityId).get();
```

The `UserWrapper` object returned is similar to the `TokenWrapper` object outlined earlier and can be iterated through as follows:

```
  for (User user : userWrapper.getUsers()) {
    System.out.println("User ID: " + user.getId());
  }

```

An entity user can be given admin privileges as follows:

```
  Entity entity = citizenApi.updateEntityAdmin(entityId, entityUser.getPersonId(), true).get();
```

This allows the user access to entity API calls for which the entity API key is used, and additionally to perform the following actions:

  * Register a data agreement

  * Regenerate the entity's signing key

  * Register the entity's encryption public key

It also allows a layer of seperation between the entity and its adminstration. If an employee is given admin privileges for the entity, they may be removed when the employee leaves with the following call:

```
  Entity entity = citizenApi.updateEntityAdmin(entityId, entityUser.getPersonId(), false).get();
```

The user's account may be then unlinked from the entity with the following call:

```
  Entity entity = citizenApi.removeEntityUser(entityId, entityUser.getPersonId()).get();
```

When data is requested by a business from a Citizen user, a 'data agreement' allows the terms of use of that data to be specified. A data agreement may be registered as follows:

```
  Entity entity = citizenApi.registerDataAgreement(
                     entityId,                       // Entity ID
                     6,                              // Agreement duration
                     TokenDurationType.MONTH,        // Agreement duration units
                     "Basic Data Agreement",         // Agreement name
                     "Agreement legal details",      // Agreement details
                     Arrays.asList("HyperMegaCorp",  // Partners with who data
                                   "AddStream",      // may be shared
                                   "ParterCo")).get();
```

The above calls specifies a data agreement where the business may hold the user's data for six month. The agreement name provides a brief description; the full agreement details are provided in the next argument. The last argument gives a list of companies with which the data may be shared.

As already covered above, a business may receive data from Citizen users with who they have a relationship via web hooks. This data may be encrypted with a public key that is registered for the entity. First a key pair is generated as follows:

```
  Optional<KeyHolder> signingKeyHolder = citizenApi.generateCryptoKeyPair("secret");

  String entityCryptoPublicKey = signingKeyHolder.get().getPublicKey();
  String entityCryptoPrivateKey = signingKeyHolder.get().getPrivateKey();
```

The private key is used for decryption and should be securely stored on the web server for which the web hooks are registered. The public key may be registered with the Citizen Service with the following call:

```
  citizenApi.registerEntityCryptoPublicKey(entityId, entityCryptoPublicKey);
```

A business may also use the Citizen Service to allow users to biometrically sign in to their website. The website includes the Citizen JavaScript modal, which prompts the user to log in. Upon successful biometric verification, a JSON Web Token (JWT) is sent via web socket from the Citizen Service to the user's browser, which can then be sent to the business's web server for verification. When the JWT is generated by the Citizen Service, it is signed by a private key specific to the business. Their web server may use the corresponding public key to verify the JWT before granting the user access. This key pair may be generated with the following call:

```
  Entity entity = citizenApi.regenerateEntitySigningKey(entityId).get();
```

The private key is kept securely on the Citizen Service and the public key may obtained through the returned Entity object as follows:

```
  String publicKey = entity.getSigningPublicKey()
```

The key is in Base 64 encoded DER format.

A business may register users on the Citizen Service for the purpose of obtaining their consent for data held about the user. Upon creation these are not yet full users, since they must complete registration themselves - an email link is sent to them from the Citizen Service inviting them to join. User's in this state are referred to as 'grey' users. The entity's public api key is used for registration, which can be obtained from the Entity object as follows:

```
  String entityPublicApiKey = entity.getPublicApiKey();
```

If a business has data relating the user 'john.doe@test.com', they may create a 'grey user' as with the following call:

```
  GreyUser greyUser = citizenApi.registerEntityUser(
                "john.doe@test.com",           // User email.
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
```

The arguments to this call may be null, with the exception of the first one - the user's email address must be present. The business may wish to check if a user is already on the Citizen Service before attempting to set up a new grey user. If the user is already registered with Citizen, a token can be sent to them instead. This may be done with the following call:

```
  UserCheck userCheck = citizenApi.checkEntityUserExists("john.doe@test.com").get();
```

To determine if the user has a fully registered or 'grey' account, the following fields in the returned UserCheck object may be used:

```
  boolean userRegistered = userCheck.getUserExists()

  boolean greyUser = userCheck.getGreyUserExists()
```
