package burp.CustomErrorException;

public class TaskTimeoutException extends RuntimeException {
    public TaskTimeoutException() {
        super();
    }

    public TaskTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }

    public TaskTimeoutException(String message) {
        super(message);
    }

    public TaskTimeoutException(Throwable cause) {
        super(cause);
    }
}