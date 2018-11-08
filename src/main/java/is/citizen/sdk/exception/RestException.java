package is.citizen.sdk.exception;

public class RestException extends RuntimeException {
    private static final long serialVersionUID = 1902144295692354943L;

    public RestException(String message) {
        super(message);
    }
}
