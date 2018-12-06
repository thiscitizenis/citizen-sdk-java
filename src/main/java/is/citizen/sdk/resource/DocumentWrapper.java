package is.citizen.sdk.resource;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import is.citizen.sdk.resource.Document;

public class DocumentWrapper implements Serializable {

private static final long serialVersionUID = 7139955853355839988L;

List<Document> documents = new ArrayList<>();

public List<Document> getDocuments() {
return documents;
}

public void setDocuments(List<Document> documents) {
this.documents = documents;
}
}
