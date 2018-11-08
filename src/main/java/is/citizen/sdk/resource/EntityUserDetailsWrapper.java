package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import java.io.Serializable;
import java.util.List;

public class EntityUserDetailsWrapper implements Serializable {
    private static final long serialVersionUID = -2167198201447442216L;

    List<EntityEmailAndUser> entityEmailAndUserList;

    public EntityUserDetailsWrapper() {
    }

    public EntityUserDetailsWrapper(List<EntityEmailAndUser> entityEmailAndUserList) {
        this.entityEmailAndUserList = entityEmailAndUserList;
    }

    public List<EntityEmailAndUser> getEntityEmailAndUserList() {
        return entityEmailAndUserList;
    }

    public void setEntityEmailAndUserList(List<EntityEmailAndUser> entityEmailAndUserList) {
        this.entityEmailAndUserList = entityEmailAndUserList;
    }

    @Override
    public String toString() {
        return "EntityUserDetailsWrapper{" +
                "entityEmailAndUserList=" + entityEmailAndUserList +
                '}';
    }
}
