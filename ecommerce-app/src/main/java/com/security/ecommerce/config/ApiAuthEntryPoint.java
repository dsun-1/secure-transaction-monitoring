package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
// logs unauthorized api access and returns 401
public class ApiAuthEntryPoint implements AuthenticationEntryPoint {

    private final SecurityEventService securityEventService;

    public ApiAuthEntryPoint(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        // emit a high severity event before sending the response
        securityEventService.logHighSeverityEvent(
            "API_AUTH_FAILURE",
            "anonymous",
            "Unauthorized API access attempt",
            "path=" + request.getRequestURI() + " | ip=" + request.getRemoteAddr()
        );
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
