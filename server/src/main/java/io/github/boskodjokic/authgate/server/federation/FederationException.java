package io.github.boskodjokic.authgate.server.federation;

/** A federated sign-in could not be completed. Always surfaces to the caller as 401. */
public class FederationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public FederationException(String message) {
        super(message);
    }

    public FederationException(String message, Throwable cause) {
        super(message, cause);
    }
}
