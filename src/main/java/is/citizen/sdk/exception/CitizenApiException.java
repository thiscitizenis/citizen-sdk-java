package is.citizen.sdk.exception;

public class CitizenApiException extends RuntimeException {
    private static final long serialVersionUID = 3162242265792374688L;

    public CitizenApiException() {
    }

    public CitizenApiException(String message) {
        super(message);
    }
}
