package is.citizen.sdk.resource;

import is.citizen.sdk.enums.EventType;
import is.citizen.sdk.resource.token.Token;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class WebHookRequestBody implements Serializable {
    private static final long serialVersionUID = 1175307180508399404L;

    private EventType eventType;
    private Token token;
    private Person person;
    private List<Document> documents;
    private JwtEncryptionDetails jwtEncryptionDetails;

    public WebHookRequestBody() {
    }

    public WebHookRequestBody(EventType eventType) {
        this.eventType = eventType;
    }

    public WebHookRequestBody addDocument(Document document) {
        if (documents == null) {
            documents = new ArrayList<>();
        }
        this.documents.add(document);
        return this;
    }

    public EventType getEventType() {
        return eventType;
    }

    public void setEventType(EventType eventType) {
        this.eventType = eventType;
    }

    public Token getToken() {
        return token;
    }

    public WebHookRequestBody setToken(Token token) {
        this.token = token;
        return this;
    }

    public Person getPerson() {
        return person;
    }

    public WebHookRequestBody setPerson(Person person) {
        this.person = person;
        return this;
    }

    public List<Document> getDocuments() {
        return documents;
    }

    public WebHookRequestBody setDocuments(List<Document> documents) {
        this.documents = documents;
        return this;
    }

    public JwtEncryptionDetails getJwtEncryptionDetails() {
        return jwtEncryptionDetails;
    }

    public WebHookRequestBody setJwtEncryptionDetails(JwtEncryptionDetails jwtEncryptionDetails) {
        this.jwtEncryptionDetails = jwtEncryptionDetails;
        return this;
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this);
    }
}
