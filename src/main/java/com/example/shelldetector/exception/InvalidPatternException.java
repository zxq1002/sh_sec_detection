package com.example.shelldetector.exception;

public class InvalidPatternException extends DetectionException {
    public InvalidPatternException(String message) {
        super(message);
    }

    public InvalidPatternException(String message, Throwable cause) {
        super(message, cause);
    }
}
