package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.Serializable;
import java.util.*;

public class Entity implements Serializable {
    private static final long serialVersionUID = 1582368575301577135L;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String id;

    @JsonView({CitizenView.User.Login.class})
    private String email;

    @JsonView({CitizenView.User.Login.class})
    private String username;

    @JsonView({CitizenView.User.FixMe.class})
    private String password;

    @JsonView({CitizenView.User.FixMe.class})
    private String passPhrase;

    @JsonView({CitizenView.User.Login.class})
    private String adminEmail;

    @JsonView({CitizenView.User.Login.class})
    private String adminUsername;

    @JsonView({CitizenView.User.FixMe.class})
    private String adminPassword;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String name;

    @JsonView({CitizenView.User.Login.class})
    private Address address;

    @JsonView({CitizenView.User.Login.class})
    private Phone phone;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String api;

    @JsonView(CitizenView.User.Register.class)
    private String mnemonicCode;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String publicKey;

    @JsonView(CitizenView.User.Register.class)
    private String authPublicKey;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String signingPublicKey;

    @JsonView({CitizenView.User.Login.class})
    private List<WebHook> webHooks = new ArrayList<>();

    @JsonView({CitizenView.User.Login.class})
    private Set<String> personIds = new HashSet<>();

    @JsonView({CitizenView.User.Login.class})
    private Set<String> hashedAdminEmails = new HashSet<>();

    @JsonView({CitizenView.User.Login.class})
    private Map<String, Email> emails = new HashMap<>();

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private boolean hasJwtPasswordLoginWebHook;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private boolean hasJwtTokenLoginWebHook;

    @JsonView({CitizenView.User.Login.class})
    private String cryptoPublicKey;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String publicApiKey;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String companyNumber;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String issuingDomain;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String tradingName;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAdminEmail() {
        return adminEmail;
    }

    public void setAdminEmail(String adminEmail) {
        this.adminEmail = adminEmail;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

    public void setAdminPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAdminUsername() {
        return adminUsername;
    }

    public void setAdminUsername(String adminUsername) {
        this.adminUsername = adminUsername;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getMnemonicCode() {
        return mnemonicCode;
    }

    public void setMnemonicCode(String mnemonicCode) {
        this.mnemonicCode = mnemonicCode;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getAuthPublicKey() {
        return authPublicKey;
    }

    public void setAuthPublicKey(String authPublicKey) {
        this.authPublicKey = authPublicKey;
    }

    public String getSigningPublicKey() {
        return signingPublicKey;
    }

    public void setSigningPublicKey(String signingPublicKey) {
        this.signingPublicKey = signingPublicKey;
    }

    public List<WebHook> getWebHooks() {
        return webHooks;
    }

    public void setWebHooks(List<WebHook> webHooks) {
        this.webHooks = webHooks;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
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

    public Set<String> getPersonIds() {
        return personIds;
    }

    public void setPersonIds(Set<String> personIds) {
        this.personIds = personIds;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public Phone getPhone() {
        return phone;
    }

    public void setPhone(Phone phone) {
        this.phone = phone;
    }

    public String getApi() {
        return api;
    }

    public void setApi(String apiKey) {
        this.api = apiKey;
    }

    public Set<String> getHashedAdminEmails() {
        return hashedAdminEmails;
    }

    public void setHashedAdminEmails(Set<String> hashedAdminEmails) {
        this.hashedAdminEmails = hashedAdminEmails;
    }

    public Map<String, Email> getEmails() {
        return emails;
    }

    public void setEmails(Map<String, Email> emails) {
        this.emails = emails;
    }

    public boolean getHasJwtPasswordLoginWebHook() {
        return hasJwtPasswordLoginWebHook;
    }

    public void setHasJwtPasswordLoginWebHook(boolean jwtPasswordLoginWebHook) {
        this.hasJwtPasswordLoginWebHook = jwtPasswordLoginWebHook;
    }

    public boolean getHasJwtTokenLoginWebHook() {
        return hasJwtTokenLoginWebHook;
    }

    public void setHasJwtTokenLoginWebHook(boolean jwtTokenLoginWebHook) {
        this.hasJwtTokenLoginWebHook = jwtTokenLoginWebHook;
    }

    public String getCryptoPublicKey() {
        return cryptoPublicKey;
    }

    public void setCryptoPublicKey(String cryptoPublicKey) {
        this.cryptoPublicKey = cryptoPublicKey;
    }

    public String getPublicApiKey() {
        return publicApiKey;
    }

    public void setPublicApiKey(String publicApiKey) {
        this.publicApiKey = publicApiKey;
    }

    public String getCompanyNumber() {
        return companyNumber;
    }

    public void setCompanyNumber(String companyNumber) {
        this.companyNumber = companyNumber;
    }

    public String getIssuingDomain() {
        return issuingDomain;
    }

    public void setIssuingDomain(String issuingDomain) {
        this.issuingDomain = issuingDomain;
    }

    public String getTradingName() {
        return tradingName;
    }

    public void setTradingName(String tradingName) {
        this.tradingName = tradingName;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
    }
}
