package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import java.io.Serializable;

public class EntityEmailAndUser implements Serializable {
    private static final long serialVersionUID = -1291462354745438411L;

    private String username;

    private String hashedEntityEmail;

    private String entityEmail;

    private boolean isAdmin;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getHashedEntityEmail() {
        return hashedEntityEmail;
    }

    public void setHashedEntityEmail(String hashedEntityEmail) {
        this.hashedEntityEmail = hashedEntityEmail;
    }

    public String getEntityEmail() {
        return entityEmail;
    }

    public void setEntityEmail(String entityEmail) {
        this.entityEmail = entityEmail;
    }

    public boolean isAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean admin) {
        isAdmin = admin;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EntityEmailAndUser that = (EntityEmailAndUser) o;

        if (isAdmin != that.isAdmin) return false;
        if (username != null ? !username.equals(that.username) : that.username != null) return false;
        if (hashedEntityEmail != null ? !hashedEntityEmail.equals(that.hashedEntityEmail) : that.hashedEntityEmail != null)
            return false;
        return entityEmail != null ? entityEmail.equals(that.entityEmail) : that.entityEmail == null;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (hashedEntityEmail != null ? hashedEntityEmail.hashCode() : 0);
        result = 31 * result + (entityEmail != null ? entityEmail.hashCode() : 0);
        result = 31 * result + (isAdmin ? 1 : 0);
        return result;
    }

    @Override
    public String toString() {
        return "EntityEmailAndUser{" +
                "username='" + username + '\'' +
                ", hashedEntityEmail='" + hashedEntityEmail + '\'' +
                ", entityEmail='" + entityEmail + '\'' +
                ", isAdmin=" + isAdmin +
                '}';
    }
}

