package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import is.citizen.sdk.enums.EventType;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class WebHook {
    @JsonView({CitizenView.User.Login.class})
    private int type;
    @JsonView({CitizenView.User.Login.class})
    private String url;

    private URI securedUrl;

    public WebHook() {
    }

    public WebHook(String url, int type) {
        this.type = type;
        this.url = url;
    }

    public WebHook addType(EventType eventType) {
        type = EventType.add(type, eventType);
        return this;
    }

    public void generateURI(String apiKey, long timestamp, String hash) throws MalformedURLException, URISyntaxException {
        securedUrl = UriComponentsBuilder.fromUri(new URL(url).toURI())
                .queryParam("apiKey", apiKey)
                .queryParam("timestamp", timestamp)
                .queryParam("hash", hash)
                .build().toUri();
    }

    public URI getURI() {
        return securedUrl;
    }

    public boolean hasEventType(EventType eventType) {
        return EventType.contains(getType(), eventType);
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getType() {
        return type;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public String toString() {
        return "WebHook{" +
                "type=" + type +
                ", url='" + url + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        WebHook webHook = (WebHook) o;

        return url != null ? url.equals(webHook.url) : webHook.url == null;
    }

    @Override
    public int hashCode() {
        return url != null ? url.hashCode() : 0;
    }

}
