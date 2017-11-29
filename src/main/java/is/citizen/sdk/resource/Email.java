package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.Serializable;

public class Email implements Serializable {
    private static final long serialVersionUID = -6761562051922726442L;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private String hashedEmail;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private String encryptedEmail;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private boolean isPrimary;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private boolean isEntityEmail;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private boolean isEntityAdmin;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private boolean isConfirmed;

    public Email() {
    }

    public String getHashedEmail() {
        return hashedEmail;
    }

    public void setHashedEmail(String hashedEmail) {
        this.hashedEmail = hashedEmail;
    }

    public void setEncryptedEmail(String encryptedEmail) {
        this.encryptedEmail = encryptedEmail;
    }

    public String getEncryptedEmail() {
        return encryptedEmail;
    }

    public void setIsPrimary(boolean isPrimary) {
        this.isPrimary = isPrimary;
    }

    public boolean getIsPrimary() {
        return isPrimary;
    }

    public void setIsEntityEmail(boolean entityEmail) {
        this.isEntityEmail = entityEmail;
    }

    public boolean getIsEntityEmail() {
        return isEntityEmail;
    }

    public boolean getIsEntityAdmin() {
        return isEntityAdmin;
    }

    public void setIsEntityAdmin(boolean isEntityAdmin) {
        this.isEntityAdmin = isEntityAdmin;
    }

    public boolean isConfirmed() {
        return isConfirmed;
    }

    public void setConfirmed(boolean confirmed) {
        isConfirmed = confirmed;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Email email = (Email) o;

        if (isPrimary != email.isPrimary) return false;
        if (isEntityEmail != email.isEntityEmail) return false;
        if (isEntityAdmin != email.isEntityAdmin) return false;
        return hashedEmail != null ? hashedEmail.equals(email.hashedEmail) : email.hashedEmail == null;
    }

    @Override
    public int hashCode() {
        int result = hashedEmail != null ? hashedEmail.hashCode() : 0;
        result = 31 * result + (isPrimary ? 1 : 0);
        result = 31 * result + (isEntityEmail ? 1 : 0);
        result = 31 * result + (isEntityAdmin ? 1 : 0);
        return result;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
    }
}
