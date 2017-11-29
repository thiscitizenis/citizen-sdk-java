package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.joda.ser.DateTimeSerializer;
import is.citizen.sdk.enums.AccessType;
import is.citizen.sdk.enums.CountryName;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.joda.time.DateTime;

import java.io.Serializable;

public class GreyUser implements Serializable {
    private static final long serialVersionUID = 5683368222602802037L;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String primaryEmail;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String username;

    @JsonView({CitizenView.User.FixMe.class})
    private String password;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private boolean passwordTemporary;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String authPublicKey;

    @JsonView(CitizenView.User.Register.class)
    private String mnemonicCode;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String apiKey;

    @JsonView(CitizenView.User.Register.class)
    private String notificationsToken;

    @JsonView({CitizenView.User.Login.class})
    private String publicKey;

    @JsonView({CitizenView.User.Login.class})
    private String personId;

    @JsonView({CitizenView.User.Login.class})
    private String title;

    @JsonView({CitizenView.User.Login.class})
    private String firstName;

    @JsonView({CitizenView.User.Login.class})
    private String middleName;

    @JsonView({CitizenView.User.Login.class})
    private String lastName;

    @JsonView({CitizenView.User.Login.class})
    private String gender;

    @JsonView({CitizenView.User.Login.class})
    @JsonSerialize(using = DateTimeSerializer.class)
    private DateTime dateOfBirth;

    @JsonView({CitizenView.User.Login.class})
    private String placeOfBirth;

    @JsonView({CitizenView.User.Login.class})
    private CountryName countryNationality;

    @JsonView({CitizenView.User.Login.class})
    private String profilePicId;

    @JsonView({CitizenView.User.Login.class})
    private Phone phone;

    @JsonView({CitizenView.User.Login.class})
    private Address address;

    @JsonView({CitizenView.User.Login.class})
    private int access;

    @JsonView({CitizenView.User.Login.class, CitizenView.User.Register.class})
    private String pin;

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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isPasswordTemporary() {
        return passwordTemporary;
    }

    public void setPasswordTemporary(boolean passwordTemporary) {
        this.passwordTemporary = passwordTemporary;
    }

    public String getAuthPublicKey() {
        return authPublicKey;
    }

    public void setAuthPublicKey(String authPublicKey) {
        this.authPublicKey = authPublicKey;
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

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getNotificationsToken() {
        return notificationsToken;
    }

    public void setNotificationsToken(String notificationsToken) {
        this.notificationsToken = notificationsToken;
    }

    public String getPersonId() {
        return personId;
    }

    public void setPersonId(String personId) {
        this.personId = personId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getFirstName() {
        return firstName;
    }

    private void updateAccessTypeIfNeeded(Object value, AccessType type) {
        if (value == null) {
            access = AccessType.remove(this.access, type);
        } else if (!AccessType.contains(this.access, type)) {
            access = AccessType.add(this.access, type);
        }
    }

    public void setFirstName(String firstName) {
        updateAccessTypeIfNeeded(firstName, AccessType.NAME);
        this.firstName = firstName;
    }

    public String getMiddleName() {
        return middleName;
    }

    public void setMiddleName(String middleName) {
        this.middleName = middleName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        updateAccessTypeIfNeeded(lastName, AccessType.NAME);
        this.lastName = lastName;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        updateAccessTypeIfNeeded(gender, AccessType.GENDER);
        this.gender = gender;
    }

    public DateTime getDateOfBirth() {
        return dateOfBirth;
    }

    public void setDateOfBirth(DateTime dateOfBirth) {
        updateAccessTypeIfNeeded(dateOfBirth, AccessType.DOB);
        this.dateOfBirth = dateOfBirth;
    }

    public String getPlaceOfBirth() {
        return placeOfBirth;
    }

    public void setPlaceOfBirth(String placeOfBirth) {
        updateAccessTypeIfNeeded(placeOfBirth, AccessType.POB);
        this.placeOfBirth = placeOfBirth;
    }

    public CountryName getCountryNationality() {
        return countryNationality;
    }

    public void setCountryNationality(CountryName countryNationality) {
        updateAccessTypeIfNeeded(countryNationality, AccessType.NATIONALITY);
        this.countryNationality = countryNationality;
    }

    public String getProfilePicId() {
        return profilePicId;
    }

    public void setProfilePicId(String profilePicId) {
        this.profilePicId = profilePicId;
    }

    public Phone getPhone() {
        return phone;
    }

    public void setPhone(Phone phone) {
        updateAccessTypeIfNeeded(phone, AccessType.PHONE);
        this.phone = phone;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        updateAccessTypeIfNeeded(address, AccessType.ADDRESS);
        this.address = address;
    }

    public int getAccess() {
        return access;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GreyUser greyUser = (GreyUser) o;

        if (primaryEmail != null ? !primaryEmail.equals(greyUser.primaryEmail) : greyUser.primaryEmail != null) return false;
        if (username != null ? !username.equals(greyUser.username) : greyUser.username != null) return false;
        if (personId != null ? !personId.equals(greyUser.personId) : greyUser.personId != null) return false;
        if (firstName != null ? !firstName.equals(greyUser.firstName) : greyUser.firstName != null) return false;
        if (lastName != null ? !lastName.equals(greyUser.lastName) : greyUser.lastName != null) return false;
        if (gender != null ? !gender.equals(greyUser.gender) : greyUser.gender != null) return false;
        return dateOfBirth != null ? dateOfBirth.equals(greyUser.dateOfBirth) : greyUser.dateOfBirth == null;
    }

    @Override
    public int hashCode() {
        int result = primaryEmail != null ? primaryEmail.hashCode() : 0;
        result = 31 * result + (username != null ? username.hashCode() : 0);
        result = 31 * result + (personId != null ? personId.hashCode() : 0);
        result = 31 * result + (firstName != null ? firstName.hashCode() : 0);
        result = 31 * result + (lastName != null ? lastName.hashCode() : 0);
        result = 31 * result + (gender != null ? gender.hashCode() : 0);
        result = 31 * result + (dateOfBirth != null ? dateOfBirth.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toStringExclude(this, "password", "mnemonicCode");
    }
}
