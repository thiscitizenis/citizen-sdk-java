package is.citizen.sdk.crypto;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import is.citizen.sdk.exception.CryptoException;
import is.citizen.sdk.util.Constant;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import org.springframework.util.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class CitizenCrypto {
    private final String CRYPTO_ALGORITHM = "RSA";
    private final int CRYPTO_KEY_SIZE = 2048;
    private final String CRYPTO_PRIVATE_KEY_ENCRYPTION_ALGO = "AES-256-GCM";
    private final String AUTH_ALGORITHM = "ECDSA";
    private final String AUTH_CURVE = "secp256r1";
    private final String AUTH_SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private final String BOUNTY_CASTLE_PROVIDER = "BC";

    public CitizenCrypto() {
        if (Security.getProvider(BOUNTY_CASTLE_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generate a key pair for use with encryption and decryption.
     *
     * @param secret password for the private key
     *
     * @return {@link KeyHolder} with the key pair encoded in Base 64.
     */
    public KeyHolder generateCryptoKeyPair(String secret) {
        KeyHolder keyHolder = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CRYPTO_ALGORITHM, BOUNTY_CASTLE_PROVIDER);
            keyGen.initialize(CRYPTO_KEY_SIZE);
            KeyPair keyPair = keyGen.generateKeyPair();

            String privateKey = encryptPrivateKey(keyPair.getPrivate(), secret);

            String publicKey = getKeyAsString(keyPair.getPublic());

            keyHolder = new KeyHolder();

            keyHolder.setPrivateKey(privateKey);
            keyHolder.setPublicKey(publicKey);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CryptoException("Unable to generate crypto key pair: " + e.getMessage(), e);
        }

        return keyHolder;
    }

    /**
     * Generate a key pair for use with authentication.
     *
     * @param secret password for the private key
     *
     * @return {@link KeyHolder} with the key pair encoded in Base 64.
     */
    public KeyHolder generateAuthenticationKeyPair(String secret) {
        KeyHolder keyHolder = null;
        try {
            ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(AUTH_CURVE);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(AUTH_ALGORITHM, BOUNTY_CASTLE_PROVIDER);
            keyGen.initialize(ecNamedCurveParameterSpec);
            KeyPair keyPair = keyGen.generateKeyPair();

            String privateKey = encryptPrivateKey(keyPair.getPrivate(), secret);

            String publicKey = getKeyAsString(keyPair.getPublic());

            keyHolder = new KeyHolder();

            keyHolder.setPrivateKey(privateKey);
            keyHolder.setPublicKey(publicKey);

        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Unable to generate auth key pair: " + e.getMessage(), e);
        }

        return keyHolder;
    }

    /**
     * Generate a key pair for use with signing data.
     *
     * @param secret password for the private key
     *
     * @return {@link KeyHolder} with the key pair encoded in Base 64.
     */
    public KeyHolder generateSigningKeyPair(String secret) {
        return generateAuthenticationKeyPair(secret);
    }

    /**
     *
     * @param dataToSign data to sign as a byte array.
     * @param encodedPrivateKey private key encoded in Base 64.
     * @param secret password for the private key.
     *
     * @return signed data encoded with Base 64.
     */
    public String signData(byte[] dataToSign, String encodedPrivateKey, String secret) {
		try {
            PrivateKey privateKey = getPrivateAuthKeyFromEncodedEncryptedString(encodedPrivateKey, secret);
			Signature signature = Signature.getInstance(AUTH_SIGNATURE_ALGORITHM);
			signature.initSign(privateKey);
			signature.update(dataToSign);
			byte[] signedText = signature.sign();
			return Base64.getEncoder().encodeToString(signedText);
		} catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeyException |
                 SignatureException e) {
            throw new CryptoException("Unable to sign message: " + e.getMessage(), e);
		}
    }

    /**
     * Verify signed data
     *
     * @param data data that was signed
     * @param signedData data signature
     * @param encodedPublicKey public key used to verify the signature in Base 64 encoded DER format.
     *
     * @return boolean indicating if the signature is valid
     *
     * @throws CryptoException
     */
    public boolean verifySignature(byte[] data, byte[] signedData, String encodedPublicKey)
            throws CryptoException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey));
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

            Signature verificationFunction = Signature.getInstance(AUTH_SIGNATURE_ALGORITHM);
            verificationFunction.initVerify(publicKey);
            verificationFunction.update(data);

             if (verificationFunction.verify(signedData)) {
                 return true;
             }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException |
                 SignatureException e) {
            throw new CryptoException("Unable to verify signature: " + e.getMessage(), e);
        }

        return false;
    }

    /**
     * Encrypt a map of {@link String} key-value pairs
     *
     * @param map the map to encrypt
     * @param publicKey public key used to encrypt the map in Base 64 DER format
     *
     * @return Optional containing the encrypted {@link Map} values are encoded using Base 64
     *
     * @throws CryptoException
     */
    public Optional<Map<String, String>> encryptMap(Map map, String publicKey)
        throws CryptoException {
        Map<String, String> encmap = new HashMap<>();

        if ((map != null) && map.keySet().size() > 0) {
            Iterator i = map.entrySet().iterator();
            while (i.hasNext()) {
                Map.Entry<String, String> pair = (Map.Entry) i.next();

                // decrypted key
                Optional<String> decproptype = Optional.ofNullable(pair.getKey());

                // decrypted val
                Optional<String> decval = Optional.ofNullable(pair.getValue());
                if (decval.isPresent()) {
                    Optional<String> encval = encryptString(decval.get(), publicKey);
                    if (encval.isPresent()) {
                        encmap.put(decproptype.get(), encval.get());
                    }
                }
            }
        }

        return Optional.ofNullable(encmap);
    }

    /**
     * Decrypt a map of {@link String} key-value pairs.
     *
     * The keys in the hash are not encrypted. The encrypted values are encoded with Base 64.
     *
     * @param map the map to decrypt
     * @param privKey private key used to decrypt the map. It is encdoded with Base 64.
     * @param secret password for the private key.
     *
     * @return decrypted map of {@link String} key-value pairs.
     *
     * @throws CryptoException
     */
    public Optional<Map<String, String>> decryptMap(Map map, String privKey, String secret)
        throws CryptoException {
        Map<String, String> decmap = new HashMap<>();
        if (map != null) {
            Iterator i = map.keySet().iterator();
            while (i.hasNext()) {
                String key = (String) i.next();
                Optional<String> encval = Optional.ofNullable((String) map.get(key));
                if (encval.isPresent()) {
                    Optional<String> decval = decryptString(encval.get(), privKey, secret);
                    if (decval.isPresent()) {
                        decmap.put(key, decval.get());
                    }
                }
            }
        }

        return Optional.ofNullable(decmap);
    }

    /**
     * Encrypt a {@link String}
     *
     * @param inputString String to encrypt
     * @param publicKey public key used to encrypt the String in Base 64 encoded DER format.
     *
     * @return encrypted String encoded with Base 64
     *
     * @throws CryptoException
     */
    public Optional<String> encryptString(String inputString, String publicKey)
        throws CryptoException {
        String encryptedText = null;

        try {
            if (StringUtils.hasText(inputString)) {
                byte[] cipherText;
                cipherText = encrypt(inputString.getBytes("UTF8"), getPublicCryptoKeyFromEncodedString(publicKey));
                encryptedText = Base64.getEncoder().encodeToString(cipherText);
            }
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException |
                 NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Unable to encrypt string: " + e.getMessage(), e);
        }

        return Optional.ofNullable(encryptedText);
    }

    /**
     * Decrypt a {@link String}
     *
     * @param inputString Base 64 encoded String to decrypt
     * @param encryptedPrivateKey private key used to decrypt the String encoded with Base 64
     * @param secret password for the private key
     *
     * @return the decrypted String
     *
     * @throws CryptoException
     */
    public Optional<String> decryptString(String inputString, String encryptedPrivateKey, String secret)
            throws CryptoException {
        String result = null;

        try {
            if (StringUtils.hasText(inputString)) {
                PrivateKey privateKey = getPrivateCryptoKeyFromEncodedEncryptedString(encryptedPrivateKey, secret);

                byte[] decryptedText = decrypt(Base64.getDecoder().decode(inputString), privateKey);
                result = new String(decryptedText, "UTF8");
            }
        } catch (IllegalBlockSizeException | IllegalArgumentException | BadPaddingException | NoSuchPaddingException
                | NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new CryptoException("Unable to decrypt string: " + e.getMessage(), e);
        }

        return Optional.ofNullable(result);
    }

    /**
     * Verify a Citizen JSON Web Token
     *
     * @param jwt JWT to verify
     * @param encodedPublicKey public key used to verify the JWT signature in Base 64 encoded DER format
     *
     * @return boolean indicating whether the verification was successful
     */
    public boolean verifyCitizenJwt(String jwt, String encodedPublicKey)
        throws CryptoException {

        PublicKey signingPublicKey = getPublicCryptoKeyFromEncodedString(encodedPublicKey);
        Claims jwtClaims = Jwts.parser().setSigningKey(signingPublicKey).parseClaimsJws(jwt).getBody();
        return jwtClaims.get(Constant.CITIZEN_JWT_AUTHENTICATED_CLAIM, Boolean.class);
    }

    /**
     * Encrypt data using public key.
     *
     * @param data The original unencrypted text
     * @param key The {@link PublicKey} with which to encrypt the data
     *
     * @return The encrypted data as a byte array
     *
     * @throws java.lang.Exception
     */
    private byte[] encrypt(byte[] data, PublicKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        // get a cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * Decrypt data using private key
     *
     * @param data The encrypted data
     * @param key  The {@link PrivateKey} with which to decrypt the data
     *
     * @return The decrypted data as a byte array
     */
    private byte[] decrypt(byte[] data, PrivateKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        byte[] decryptedText;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        decryptedText = cipher.doFinal(data);
        return decryptedText;
    }

    /**
     * Convert a Key to string encoded as Base 64
     *
     * @param key The key (private or public)
     * @return A string representation of the key
     */
    private String getKeyAsString(Key key) {
        byte[] keyBytes = key.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /**
     * Encrypt a private key and convert it to a Base 64 encoded {@link String}
     *
     * @param key {@link PrivateKey} to encrypt and encode
     * @param secret password for the private key
     *
     * @return Base 64 encoded encrypted private key
     *
     * @throws IOException
     */
    private String encryptPrivateKey(PrivateKey key, String secret) throws IOException {
        StringWriter keyWriter = new StringWriter();

        JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder(CRYPTO_PRIVATE_KEY_ENCRYPTION_ALGO);

        PEMEncryptor pemEncryptor = builder.build(secret.toCharArray());

        JcaPEMWriter jcaPemWriter = new JcaPEMWriter(keyWriter);
        jcaPemWriter.writeObject(key, pemEncryptor);

        jcaPemWriter.flush();

        String encryptedPrivateKey = keyWriter.toString();

        return Base64.getEncoder().encodeToString(encryptedPrivateKey.getBytes("utf-8"));
    }

     /**
     * Decrypt a private crypto key and convert it to {@link PrivateKey}
     *
     * @param encodedEncryptedPrivateKey encrypted private key, can be base 64 encoded
     * @param password            password to decrypt
      *
     * @return {@link PrivateKey}
     */
    public PrivateKey getPrivateCryptoKeyFromEncodedEncryptedString(final String encodedEncryptedPrivateKey, final String password)
            throws CryptoException {

        try {
            String encryptedPrivateKey = new String(Base64.getDecoder().decode(encodedEncryptedPrivateKey));

            PEMKeyPair pemKeyPair = getEncryptedPEMKeyPair(encryptedPrivateKey, password);

            JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();

            return jcaPEMKeyConverter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            throw new CryptoException("Unable to get crypto private key from encoded string", e);
        }
    }

    /**
     * Generates a {@link PublicKey} from a Base 64 encoded DER public crypto key
     *
     * @param key Base 64 encoded string which represents the key
     *
     * @return {@link PublicKey}
     *
     * @throws java.lang.Exception
     */
    public PublicKey getPublicCryptoKeyFromEncodedString(String key)
        throws CryptoException {

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_ALGORITHM);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
            return keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to get crypto public key from encoded string", e);
        }
    }

    /**
     * Decrypt a private crypto key and convert it to {@link PrivateKey}
     *
     * @param encodedEncryptedPrivateKey encrypted private key, can be base 64 encoded
     * @param password            password to decrypt
      *
     * @return {@link PrivateKey}
     */
    public PrivateKey getPrivateAuthKeyFromEncodedEncryptedString(final String encodedEncryptedPrivateKey, final String password)
            throws CryptoException {
        try {
            String encryptedPrivateKey = new String(Base64.getDecoder().decode(encodedEncryptedPrivateKey));
            PEMKeyPair pemKeyPair = getEncryptedPEMKeyPair(encryptedPrivateKey, password);
            JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();

            return jcaPEMKeyConverter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            throw new CryptoException("Unable to get private key from encoded string", e);
        }
    }

    /**
     * Generates a {@link PublicKey} from a Base 64 encoded DER public crypto key
     *
     * @param key Base 64 encoded string which represents the key
     *
     * @return {@link PublicKey}
     *
     * @throws java.lang.Exception
     */
    public PublicKey getPublicAuthKeyFromEncodedString(String key)
        throws CryptoException {

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(AUTH_ALGORITHM);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
            return keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to get auth public key from encoded string", e);
        }
    }

    /**
     * Creates a {@link PEMKeyPair} from encrypted private key
     *
     * @param encryptedKey encrypted private key encoded with Base 64
     * @param secret password for the private key
     *
     * @return {@link PEMKeyPair}
     *
     * @throws IOException in case can't read the key
     */
    private PEMKeyPair getEncryptedPEMKeyPair(final String encryptedKey, final String secret)
            throws CryptoException {
        // Read Encrypted PEM format now
        StringReader privateKeyReader = new StringReader(encryptedKey);

        PEMParser pemParser = new PEMParser(privateKeyReader);

        Object pemObject = null;
        try {
            pemObject = pemParser.readObject();
        } catch (IOException e) {
            throw new CryptoException("Unable to read PEM object: " + e.getMessage(), e);
        }

        if (pemObject == null) {
            throw new CryptoException("PEM object cannot be null");
        } else if (!(pemObject instanceof PEMEncryptedKeyPair)) {
            throw new CryptoException("PEM object not encrypted key pair");
        }

        PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) pemObject;

        JcePEMDecryptorProviderBuilder decryptorProviderBuilder = new JcePEMDecryptorProviderBuilder();

        PEMKeyPair pemKeyPair = null;

        try {
            PEMDecryptorProvider pemDecryptorProvider = decryptorProviderBuilder.build(secret.toCharArray());
            pemKeyPair = encryptedKeyPair.decryptKeyPair(pemDecryptorProvider);
        } catch (IOException e) {
            throw new CryptoException("Unable to get encrypted PEM key pair: " + e.getMessage(), e);
        }

        return pemKeyPair;
    }
}
