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
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class CitizenCrypto {
    private static final String CRYPTO_ALGORITHM = "RSA";
    private static final int CRYPTO_KEY_SIZE = 2048;
    private static final String CRYPTO_PRIVATE_KEY_ENCRYPTION_ALGO = "AES-256-GCM";
    private static final String AUTH_ALGORITHM = "ECDSA";
    private static final String AUTH_CURVE = "secp256r1";
    private static final String AUTH_SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String BOUNTY_CASTLE_PROVIDER = "BC";

    static {
        if (Security.getProvider(BOUNTY_CASTLE_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static Optional<KeyHolder> generateCryptoKeyPair(String secret) {
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
            throw new CryptoException("CitizenCrypto exception: " + e.getMessage());
        }

        return Optional.ofNullable(keyHolder);
    }

    public static Optional<KeyHolder> generateAuthenticationKeyPair(String secret) {
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
            throw new CryptoException("CitizenCrypto exception: " + e.getMessage());
        }

        return Optional.ofNullable(keyHolder);
    }

    public static Optional<KeyHolder> generateSigningKeyPair(String secret) {
        return generateAuthenticationKeyPair(secret);
    }

    public static String signData(byte[] dataToSign, String encodedPrivateKey, String password) {
		try {
            PrivateKey privateKey = getPrivateKeyFromEncodedEncryptedString(encodedPrivateKey, password);
			Signature signature = Signature.getInstance(AUTH_SIGNATURE_ALGORITHM);
			signature.initSign(privateKey);
			signature.update(dataToSign);
			byte[] signedText = signature.sign();
			return Base64.getEncoder().encodeToString(signedText);
		} catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeyException |
                 IOException | SignatureException e) {
            throw new CryptoException(e.getMessage());
		}
    }

    public static boolean verifySignature(byte[] data, byte[] signedData, String encodedPublicKey)
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
                 SignatureException e)
        {
            throw new CryptoException("Unable to verify signature: " + e.getMessage());
        }

        return false;
    }

    public Optional<Map> encryptMap(Map map, String publicKey)
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

    public static Optional<Map> decryptMap(Map map, String privKey, String secret)
        throws CryptoException {
        Map decmap = new HashMap<>();
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

    public static Optional<String> encryptString(String inputString, String publicKey)
        throws CryptoException {
        String encryptedText = null;

        try {
            if (StringUtils.hasText(inputString)) {
                byte[] cipherText;
                cipherText = encrypt(inputString.getBytes("UTF8"), getPublicKeyFromEncodedString(publicKey));
                encryptedText = Base64.getEncoder().encodeToString(cipherText);
            }
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }

        return Optional.ofNullable(encryptedText);
    }


    public static Optional<String> decryptString(String inputString, String encryptedPrivateKey, String keyPassword)
            throws CryptoException {
        String result = null;

        try {
            if (StringUtils.hasText(inputString)) {
                PrivateKey privateKey = getPrivateKeyFromEncodedEncryptedString(encryptedPrivateKey, keyPassword);

                byte[] decryptedText = decrypt(Base64.getDecoder().decode(inputString), privateKey);
                result = new String(decryptedText, "UTF8");
            }
        } catch (IllegalBlockSizeException | IllegalArgumentException | BadPaddingException | NoSuchPaddingException
                | NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new CryptoException(e.getMessage());
        }

        return Optional.ofNullable(result);
    }

    public static boolean verifyCitizenJwt(String jwt, String encodedPublicKey) {
        try {
            PublicKey signingPublicKey = getPublicKeyFromEncodedString(encodedPublicKey);
            Claims jwtClaims = Jwts.parser().setSigningKey(signingPublicKey).parseClaimsJws(jwt).getBody();
            return jwtClaims.get(Constant.CITIZEN_JWT_AUTHENTICATED_CLAIM, Boolean.class);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /**
     * Encrypt a text using public key.
     *
     * @param text The original unencrypted text
     * @param key  The public key
     * @return Encrypted text
     * @throws java.lang.Exception
     */
    private static byte[] encrypt(byte[] text, PublicKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        // get a cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(text);
    }

    /**
     * Decrypt text using private key
     *
     * @param text The encrypted text
     * @param key  The private key
     * @return The unencrypted text
     */
    private static byte[] decrypt(byte[] text, PrivateKey key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        byte[] decryptedText;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        decryptedText = cipher.doFinal(text);
        return decryptedText;
    }

    /**
     * Convert a Key to string encoded as Base 64
     *
     * @param key The key (private or public)
     * @return A string representation of the key
     */
    private static String getKeyAsString(Key key) {
        byte[] keyBytes = key.getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    private static String encryptPrivateKey(PrivateKey key, String secret) throws IOException {
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
     * Decrypt a private key and converts to {@link PrivateKey}
     *
     * @param encodedEncryptedPrivateKey encrypted private key, can be base 64 encoded
     * @param password            password to decrypt
     * @return {@link PrivateKey}
     */
    private static PrivateKey getPrivateKeyFromEncodedEncryptedString(final String encodedEncryptedPrivateKey, final String password)
            throws IOException {

        String encryptedPrivateKey = new String(Base64.getDecoder().decode(encodedEncryptedPrivateKey));

        PEMKeyPair pemKeyPair = getEncryptedPEMKeyPair(encryptedPrivateKey, password);

        JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();

        return jcaPEMKeyConverter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
    }

    /**
     * Generates Public Key from BASE64 encoded string
     *
     * @param key BASE64 encoded string which represents the key
     * @return The PublicKey
     * @throws java.lang.Exception
     */
    public static PublicKey getPublicKeyFromEncodedString(String key)
        throws InvalidKeySpecException, NoSuchAlgorithmException {

        KeyFactory keyFactory = KeyFactory.getInstance(CRYPTO_ALGORITHM);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * Creates a {@link PEMKeyPair} from encrypted key
     *
     * @param encryptedKey encrypted key
     * @param password     password to decrypt
     * @return {@link PEMKeyPair}
     * @throws IOException in case can't read the key
     */
    private static PEMKeyPair getEncryptedPEMKeyPair(final String encryptedKey, final String password)
            throws IOException {
        // Read Encrypted PEM format now
        StringReader privateKeyReader = new StringReader(encryptedKey);

        PEMParser pemParser = new PEMParser(privateKeyReader);
        Object pemObject = pemParser.readObject();

        if (pemObject == null) {
            throw new IOException();
        } else if (!(pemObject instanceof PEMEncryptedKeyPair)) {
            throw new IOException();
        }

        PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) pemObject;

        JcePEMDecryptorProviderBuilder decryptorProviderBuilder = new JcePEMDecryptorProviderBuilder();

        PEMKeyPair pemKeyPair = null;

        try {
            PEMDecryptorProvider pemDecryptorProvider = decryptorProviderBuilder.build(password.toCharArray());
            pemKeyPair = encryptedKeyPair.decryptKeyPair(pemDecryptorProvider);
        } catch (EncryptionException e) {
            throw new IOException(e);
        }

        return pemKeyPair;
    }
}
