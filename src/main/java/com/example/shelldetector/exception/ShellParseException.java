package com.example.shelldetector.exception;

public class ShellParseException extends DetectionException {
    public ShellParseException(String message) {
        super(message);
    }

    public ShellParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
