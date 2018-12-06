package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import is.citizen.sdk.enums.TokenDurationType;

import java.io.Serializable;
import java.util.List;

public class DataAgreement implements Serializable {
    private static final long serialVersionUID = 8918373327319260316L;

    @JsonView({CitizenView.User.Login.class})
    private String name;

    @JsonView({CitizenView.User.Login.class})
    private String purpose;

    @JsonView({CitizenView.User.Login.class})
    private int duration;

    @JsonView({CitizenView.User.Login.class})
    private TokenDurationType durationType;

    @JsonView({CitizenView.User.Login.class})
    private List<String> sharedTo;

    public DataAgreement() {
    }

    public DataAgreement(String name, String purpose, int duration, TokenDurationType durationType, List<String> sharedTo) {
        this.name = name;
        this.purpose = purpose;
        this.duration = duration;
        this.durationType = durationType;
        this.sharedTo = sharedTo;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    public int getDuration() {
        return duration;
    }

    public void setDuration(int duration) {
        this.duration = duration;
    }

    public TokenDurationType getDurationType() {
        return durationType;
    }

    public void setDurationType(TokenDurationType durationType) {
        this.durationType = durationType;
    }

    public List<String> getSharedTo() {
        return sharedTo;
    }

    public void setSharedTo(List<String> sharedTo) {
        this.sharedTo = sharedTo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DataAgreement that = (DataAgreement) o;

        if (duration != that.duration) return false;
        if (name != null ? !name.equals(that.name) : that.name != null) return false;
        if (purpose != null ? !purpose.equals(that.purpose) : that.purpose != null) return false;
        return durationType == that.durationType;
    }

    @Override
    public int hashCode() {
        int result = name != null ? name.hashCode() : 0;
        result = 31 * result + (purpose != null ? purpose.hashCode() : 0);
        result = 31 * result + duration;
        result = 31 * result + (durationType != null ? durationType.hashCode() : 0);
        return result;
    }
}
