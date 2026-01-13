package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.regex.Pattern;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 5)
// scans request parameters for simple sqli and xss patterns
public class RequestInspectionFilter extends OncePerRequestFilter {

    private static final Pattern SQLI_PATTERN = Pattern.compile(
        "(?i)(\\bselect\\b|\\binsert\\b|\\bupdate\\b|\\bdelete\\b|\\bdrop\\b|\\bunion\\b|\\bor\\b\\s*['\\\"]?\\w+['\\\"]?\\s*=\\s*['\\\"]?\\w+['\\\"]?|--|;--|/\\*|\\*/)"
    );
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)(<script|<img|onerror\\s*=|onload\\s*=|javascript:)"
    );

    private final SecurityEventService securityEventService;

    public RequestInspectionFilter(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        // log at most one sqli and one xss signal per request
        boolean loggedSql = false;
        boolean loggedXss = false;
        Enumeration<String> paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()) {
            String name = paramNames.nextElement();
            String[] values = request.getParameterValues(name);
            if (values == null) {
                continue;
            }
            for (String value : values) {
                if (!loggedSql && value != null && SQLI_PATTERN.matcher(value).find()) {
                    logEvent("SQL_INJECTION_ATTEMPT", request, name, value);
                    loggedSql = true;
                }
                if (!loggedXss && value != null && XSS_PATTERN.matcher(value).find()) {
                    logEvent("XSS_ATTEMPT", request, name, value);
                    loggedXss = true;
                }
                if (loggedSql && loggedXss) {
                    break;
                }
            }
            if (loggedSql && loggedXss) {
                break;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void logEvent(String eventType, HttpServletRequest request, String paramName, String paramValue) {
        String username = resolveUsername();
        // trim and cap payload to keep logs small
        String payload = paramValue == null ? "" : paramValue.replaceAll("\\s+", " ").trim();
        if (payload.length() > 120) {
            payload = payload.substring(0, 120) + "...";
        }
        String description = "Suspicious input detected on " + request.getRequestURI();
        String additional = "param=" + paramName + " | value=" + payload + " | ip=" + request.getRemoteAddr();
        securityEventService.logHighSeverityEvent(eventType, username, description, additional);
    }

    private String resolveUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "anonymous";
        }
        return authentication.getName();
    }
}
