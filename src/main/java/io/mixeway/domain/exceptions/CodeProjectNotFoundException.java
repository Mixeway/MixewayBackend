package io.mixeway.domain.exceptions;

/**
 * Exception thrown when a CodeProject is not found.
 */
public class CodeProjectNotFoundException extends RuntimeException {

    /**
     * Constructs a new CodeProjectNotFoundException with {@code null} as its detail message.
     */
    public CodeProjectNotFoundException() {
        super();
    }

    /**
     * Constructs a new CodeProjectNotFoundException with the specified detail message.
     *
     * @param message the detail message
     */
    public CodeProjectNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructs a new CodeProjectNotFoundException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause (a throwable cause saved for later retrieval by the {@link #getCause()} method)
     */
    public CodeProjectNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new CodeProjectNotFoundException with the specified cause.
     *
     * @param cause the cause (a throwable cause saved for later retrieval by the {@link #getCause()} method)
     */
    public CodeProjectNotFoundException(Throwable cause) {
        super(cause);
    }
}
