package is.citizen.sdk.resource;

import java.io.Serializable;

public class JwtLoginParameters implements Serializable {
    private static final long serialVersionUID = -3163485061722122492L;

    private String userEmail;

    private String thirdPartySessionIdentifier;

    private String citizenSessionNonce;

    private String browserPublicKey;

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getThirdPartySessionIdentifier() {
        return thirdPartySessionIdentifier;
    }

    public void setThirdPartySessionIdentifier(String thirdPartySessionIdentifier) {
        this.thirdPartySessionIdentifier = thirdPartySessionIdentifier;
    }

    public String getCitizenSessionNonce() {
        return citizenSessionNonce;
    }

    public void setCitizenSessionNonce(String citizenSessionNonce) {
        this.citizenSessionNonce = citizenSessionNonce;
    }

    public String getBrowserPublicKey() {
        return browserPublicKey;
    }

    public void setBrowserPublicKey(String browserPublicKey) {
        this.browserPublicKey = browserPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JwtLoginParameters that = (JwtLoginParameters) o;

        if (userEmail != null ? !userEmail.equals(that.userEmail) : that.userEmail != null) return false;
        if (thirdPartySessionIdentifier != null ? !thirdPartySessionIdentifier.equals(that.thirdPartySessionIdentifier) : that.thirdPartySessionIdentifier != null)
            return false;
        if (citizenSessionNonce != null ? !citizenSessionNonce.equals(that.citizenSessionNonce) : that.citizenSessionNonce != null)
            return false;
        return browserPublicKey != null ? browserPublicKey.equals(that.browserPublicKey) : that.browserPublicKey == null;
    }

    @Override
    public int hashCode() {
        int result = userEmail != null ? userEmail.hashCode() : 0;
        result = 31 * result + (thirdPartySessionIdentifier != null ? thirdPartySessionIdentifier.hashCode() : 0);
        result = 31 * result + (citizenSessionNonce != null ? citizenSessionNonce.hashCode() : 0);
        result = 31 * result + (browserPublicKey != null ? browserPublicKey.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "JwtLoginParameters{" +
                "userEmail='" + userEmail + '\'' +
                ", thirdPartySessionIdentifier='" + thirdPartySessionIdentifier + '\'' +
                ", citizenSessionNonce='" + citizenSessionNonce + '\'' +
                ", browserPublicKey='" + browserPublicKey + '\'' +
                '}';
    }
}

