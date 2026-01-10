package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SecurityAccessDeniedHandler implements AccessDeniedHandler {

    private final SecurityEventService securityEventService;
    private final AccessDeniedHandlerImpl delegate = new AccessDeniedHandlerImpl();

    public SecurityAccessDeniedHandler(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        if (accessDeniedException instanceof CsrfException) {
            securityEventService.logHighSeverityEvent(
                "CSRF_VIOLATION",
                "anonymous",
                "CSRF token rejected",
                "path=" + request.getRequestURI() + " | ip=" + request.getRemoteAddr()
            );
        }
        String path = request.getRequestURI();
        if (path != null && path.startsWith("/api/security")) {
            String username = request.getUserPrincipal() != null
                ? request.getUserPrincipal().getName()
                : "anonymous";
            securityEventService.logHighSeverityEvent(
                "PRIVILEGE_ESCALATION_ATTEMPT",
                username,
                "Unauthorized access to admin endpoint",
                "path=" + path + " | ip=" + request.getRemoteAddr()
            );
        }
        delegate.handle(request, response, accessDeniedException);
    }
}
