package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public final class User implements Serializable {

    private static final long serialVersionUID = -2462246955420639790L;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String primaryEmail;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String username;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String id;

    @JsonView({CitizenView.User.FixMe.class})
    private String password;

    @JsonView({CitizenView.User.FixMe.class})
    private String passPhrase;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private boolean passwordTemporary;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class, CitizenView.User.Verify.class})
    private String authPublicKey;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String mnemonicCode;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String publicKey;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String apiKey;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private String personId;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private String notificationsToken;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private Map<String, Email> emails = new HashMap<>();

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private String entityEmail;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private boolean isAdmin;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private String entityId;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private boolean hasSecret;

    public String getPersonId() {
        return personId;
    }

    public void setPersonId(String personId) {
        this.personId = personId;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getPrimaryEmail() {
        return primaryEmail;
    }

    public void setPrimaryEmail(String primaryEmail) {
        this.primaryEmail = primaryEmail;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return the user's username
     * @deprecated Namespace is now called username. So you should use username instead. NOTE: What used to be username is now called primaryEmail
     */
    @Deprecated
    @JsonIgnore
    public String getNamespace() {
        return username;
    }

    /**
     * @param namespace set's the username of the user to this value
     * @deprecated Namespace is now called username. So you should use username instead. NOTE: What used to be username is now called primaryEmail
     */
    @Deprecated
    @JsonIgnore
    public void setNamespace(String namespace) {
        this.username = namespace;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassPhrase() {
        return passPhrase;
    }

    public void setPassPhrase(String passPhrase) {
        this.passPhrase = passPhrase;
    }

    public boolean getPasswordTemporary() {
        return passwordTemporary;
    }

    public void setPasswordTemporary(boolean passwordTemporary) {
        this.passwordTemporary = passwordTemporary;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getAuthPublicKey() {
        return authPublicKey;
    }

    public void setAuthPublicKey(String authPublicKey) {
        this.authPublicKey = authPublicKey;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getMnemonicCode() {
        return mnemonicCode;
    }

    public void setMnemonicCode(String mnemonicCode) {
        this.mnemonicCode = mnemonicCode;
    }

    public String getNotificationsToken() {
        return notificationsToken;
    }

    public void setNotificationsToken(String notificationsToken) {
        this.notificationsToken = notificationsToken;
    }

    public void setEmails(Map<String, Email> emails) {
        this.emails = emails;
    }

    public Map<String, Email> getEmails() {
        return emails;
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

    public void setIsAdmin(boolean admin) {
        isAdmin = admin;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public boolean hasSecret() {
        return hasSecret;
    }

    public void setHasSecret(boolean hasSecret) {
        this.hasSecret = hasSecret;
    }

    @Override
    public int hashCode() {
        return Objects.hash(primaryEmail, password, id, apiKey, personId);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final User other = (User) obj;
        return Objects.equals(this.primaryEmail, other.primaryEmail) &&
                Objects.equals(this.password, other.password) &&
                Objects.equals(this.apiKey, other.apiKey) &&
                Objects.equals(this.personId, other.personId) &&
                Objects.equals(this.id, other.id);
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toStringExclude(this, "password", "mnemonicCode");
    }
}

