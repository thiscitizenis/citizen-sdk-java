package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.Serializable;
import java.util.Objects;

//TODO: Write tests for different views
public class ApiKey implements Serializable {

    private static final long serialVersionUID = 6299646687165629441L;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private String apiKey;

    @JsonView({CitizenView.User.Register.class, CitizenView.User.Login.class})
    private boolean enabled;

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public int hashCode() {
        return Objects.hash(apiKey, enabled);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final ApiKey other = (ApiKey) obj;
        return Objects.equals(this.apiKey, other.apiKey) && Objects.equals(this.enabled, other.enabled);
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
    }
}
