package com.security.ecommerce.controller;

import com.security.ecommerce.service.SecurityEventService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@ControllerAdvice
public class SecurityExceptionHandler {

    private final SecurityEventService securityEventService;

    public SecurityExceptionHandler(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<String> handleTypeMismatch(MethodArgumentTypeMismatchException ex,
                                                     HttpServletRequest request) {
        String name = ex.getName() == null ? "" : ex.getName();
        if ("quantity".equalsIgnoreCase(name)) {
            securityEventService.logHighSeverityEvent(
                "AMOUNT_TAMPERING",
                "anonymous",
                "Invalid quantity submitted",
                "value=" + ex.getValue() + " | path=" + request.getRequestURI()
            );
        }
        return ResponseEntity.badRequest().body("Invalid request");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<String> handleUnsupportedMedia(HttpMediaTypeNotSupportedException ex,
                                                         HttpServletRequest request) {
        String contentType = "";
        var mediaType = ex.getContentType();
        if (mediaType != null) {
            contentType = mediaType.toString();
        }
        if (!contentType.isEmpty() && contentType.toLowerCase().contains("application/x-java-serialized-object")) {
            securityEventService.logHighSeverityEvent(
                "DESERIALIZATION_ATTEMPT",
                "anonymous",
                "Serialized payload rejected",
                "path=" + request.getRequestURI()
            );
        }
        return ResponseEntity.status(415).body("Unsupported media type");
    }
}
