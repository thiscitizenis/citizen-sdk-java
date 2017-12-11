package is.citizen.sdk.resource;

import java.io.Serializable;
import java.util.List;

public class EmailList implements Serializable {
    private static final long serialVersionUID = -8263988583695197416L;

    private List<Email> emails;

    public void setEmails(List<Email> emails) {
        this.emails = emails;
    }

    public List<Email> getEmails() {
        return emails;
    }
}
