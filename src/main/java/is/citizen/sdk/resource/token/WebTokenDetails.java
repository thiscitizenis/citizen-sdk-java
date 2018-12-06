package is.citizen.sdk.resource.token;

import is.citizen.sdk.enums.TokenStatus;

import java.io.Serializable;

public class WebTokenDetails implements Serializable {

    private static final long serialVersionUID = 4784630110446530509L;

    private String nonce;
    private String remoteAddress;
    private TokenStatus tokenStatus;
    private Token token;

    public WebTokenDetails() {
        tokenStatus = TokenStatus.REQUESTED;
    }

    public WebTokenDetails(String nonce) {
        this.nonce = nonce;
        this.tokenStatus = TokenStatus.REQUESTED;
    }

    public WebTokenDetails(String nonce, TokenStatus tokenStatus) {
        this.nonce = nonce;
        this.tokenStatus = tokenStatus;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public void setRemoteAddress(String remoteAddress) {
        this.remoteAddress = remoteAddress;
    }

    public TokenStatus getTokenStatus() {
        return tokenStatus;
    }

    public void setTokenStatus(TokenStatus tokenStatus) {
        this.tokenStatus = tokenStatus;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }
}
