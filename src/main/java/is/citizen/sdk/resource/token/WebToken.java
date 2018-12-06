package is.citizen.sdk.resource.token;

public class WebToken extends Token {

    private static final long serialVersionUID = 4781750110446539469L;

    private String nonce;

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }
}
