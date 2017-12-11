package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;

import java.io.Serializable;
import java.util.List;

public class UserWrapper implements Serializable {
    private static final long serialVersionUID = -8366422070407548235L;

    @JsonView({CitizenView.User.Login.class})
    List<Person> persons;

    public UserWrapper() {
    }

    public UserWrapper(List<Person> persons) {
        this.persons = persons;
    }

    public List<Person> getPersons() {
        return persons;
    }

    public void setPersons(List<Person> persons) {
        this.persons = persons;
    }

    @Override
    public String toString() {
        return "UserWrapper{" +
                "persons=" + persons +
                '}';
    }
}
