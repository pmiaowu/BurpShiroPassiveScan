package burp.CustomErrorException;

public class DiffPageException extends RuntimeException {
    public DiffPageException() {
        super();
    }

    public DiffPageException(String message, Throwable cause) {
        super(message, cause);
    }

    public DiffPageException(String message) {
        super(message);
    }

    public DiffPageException(Throwable cause) {
        super(cause);
    }
}