package is.citizen.sdk.crypto;

import java.io.Serializable;
import java.util.Objects;

/**
 * Simple holder class for public, private key strings
 */
public class KeyHolder implements Serializable {

    private static final long serialVersionUID = -7087795592810256957L;

    /**
     * Base 64 encoded public key string
     */
    private String publicKey;

    /**
     * Base 64 encoded private key string, encrypted with some password
     */
    private String privateKey;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey, privateKey);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final KeyHolder other = (KeyHolder) obj;
        return Objects.equals(this.publicKey, other.publicKey) && Objects.equals(this.privateKey, other.privateKey);
    }
}
