package is.citizen.sdk.resource;

import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.joda.time.DateTime;

import is.citizen.sdk.enums.DocumentType;

public class Document extends BaseEncryptedAsset {

    private static final long serialVersionUID = -7982802169093033099L;

    @JsonView({CitizenView.User.Login.class})
    private String id;

    /**
     * id of original document (parent)
     */
    private String documentId;
    private String tokenID;

    @Deprecated
    private String personId;
    private String accountId;
    private String previewDocumentId;
    private String name;
    private String fileName;

    private boolean isPreview; // set this to true to return previews for posted documents

    private DocumentType documentType;
    private DateTime creationDate;

    private boolean isPhotoID;
    private boolean isAddressValidation;
    private boolean isFaceValidated;

    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }

    /**
     * @deprecated Use {@link Document#getAccountId()} instead
     * @return
     */
    @Deprecated
    public String getPersonId() { return personId; }

    /**
     * @deprecated use {@link Document#setAccountId(String)} instead
     * @param personId
     */
    @Deprecated
    public void setPersonId(String personId) { this.personId = personId; }

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    public String getPreviewDocumentId() { return previewDocumentId; }

    public void setPreviewDocumentId(String previewDocumentId) { this.previewDocumentId = previewDocumentId; }

    public boolean isPreview() { return isPreview; }

    public void setPreview(boolean preview) { isPreview = preview; }

    public DateTime getCreationDate() { return creationDate; }

    public void setCreationDate(DateTime creationDate) { this.creationDate = creationDate; }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getFileName() { return fileName; }

    public void setFileName(String fileName) { this.fileName = fileName; }

    public DocumentType getDocumentType() {
            return documentType;
    }

    public void setDocumentType(DocumentType documentType) {
        this.documentType = documentType;
    }

    public boolean getIsPhotoID() {
        return isPhotoID;
    }

    public void setPhotoID(boolean photoID) {
        isPhotoID = photoID;
    }

    public boolean getIsAddressValidation() {
        return isAddressValidation;
    }

    public void setAddressValidation(boolean addressValidation) {
        isAddressValidation = addressValidation;
    }

    public boolean isFaceValidated() {
        return isFaceValidated;
    }

    public void setFaceValidated(boolean faceValidated) {
        this.isFaceValidated = faceValidated;
    }

    public String getDocumentId() {
        return documentId;
    }

    public void setDocumentId(String documentId) {
        this.documentId = documentId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Document document = (Document) o;

        if (isPhotoID != document.isPhotoID) return false;
        if (isAddressValidation != document.isAddressValidation) return false;
        if (isPreview != document.isPreview) return false;
        if (id != null ? !id.equals(document.id) : document.id != null) return false;
        if (personId != null ? !personId.equals(document.personId) : document.personId != null) return false;
        if (previewDocumentId != null ? !previewDocumentId.equals(document.previewDocumentId) : document.previewDocumentId != null)
            return false;
        if (name != null ? !name.equals(document.name) : document.name != null) return false;
        if (fileName != null ? !fileName.equals(document.fileName) : document.fileName != null) return false;
        if (documentType != document.documentType) return false;
        return creationDate != null ? creationDate.equals(document.creationDate) : document.creationDate == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (personId != null ? personId.hashCode() : 0);
        result = 31 * result + (previewDocumentId != null ? previewDocumentId.hashCode() : 0);
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + (fileName != null ? fileName.hashCode() : 0);
        result = 31 * result + (isPreview ? 1 : 0);
        result = 31 * result + (documentType != null ? documentType.hashCode() : 0);
        result = 31 * result + (creationDate != null ? creationDate.hashCode() : 0);
        result = 31 * result + (isPhotoID ? 1 : 0);
        result = 31 * result + (isAddressValidation ? 1 : 0);
        result = 31 * result + (isPhotoID ? 1 : 0);
        result = 31 * result + (isAddressValidation ? 1 : 0);
        return result;
    }
    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this);
    }
}
