package is.citizen.sdk.resource;

import is.citizen.sdk.enums.TokenDurationType;

import java.io.Serializable;
import java.util.List;

public class DataAgreement implements Serializable {
    private static final long serialVersionUID = 8918373327319260316L;

    private String name;
    private String purpose;
    private int duration;
    private TokenDurationType durationType;
    private List<String> sharedTo;

    public DataAgreement() {
    }

    public DataAgreement(String name, String purpose, int duration, List<String> sharedTo) {
        this.name = name;
        this.purpose = purpose;
        this.duration = duration;
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
}
