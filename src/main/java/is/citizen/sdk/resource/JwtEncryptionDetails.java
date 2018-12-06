package is.citizen.sdk.resource;

import java.io.Serializable;

public class JwtEncryptionDetails implements Serializable {
    private static final long serialVersionUID = 1214976959371893643L;

    private String jwtCipher;
    private String jwtIv;
    private String key;

    public String getJwtCipher() {
        return jwtCipher;
    }

    public void setJwtCipher(String jwtCipher) {
        this.jwtCipher = jwtCipher;
    }

    public String getJwtIv() {
        return jwtIv;
    }

    public void setJwtIv(String jwtIv) {
        this.jwtIv = jwtIv;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JwtEncryptionDetails that = (JwtEncryptionDetails) o;

        if (jwtCipher != null ? !jwtCipher.equals(that.jwtCipher) : that.jwtCipher != null) return false;
        if (jwtIv != null ? !jwtIv.equals(that.jwtIv) : that.jwtIv != null) return false;
        return key != null ? key.equals(that.key) : that.key == null;
    }

    @Override
    public int hashCode() {
        int result = jwtCipher != null ? jwtCipher.hashCode() : 0;
        result = 31 * result + (jwtIv != null ? jwtIv.hashCode() : 0);
        result = 31 * result + (key != null ? key.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "JwtEncryptionDetails{" +
                "jwtCipher='" + jwtCipher + '\'' +
                ", jwtIv='" + jwtIv + '\'' +
                ", key='" + key + '\'' +
                '}';
    }
}
