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
  - Log in with a third party entity signed JSON Web Token.

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
