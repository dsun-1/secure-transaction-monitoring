package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 15)
// watches sessions for invalid ids and context mismatch
public class SessionSecurityFilter extends OncePerRequestFilter {

    private static final String SESSION_IP = "session_ip";
    private static final String SESSION_UA = "session_user_agent";
    private static final String SESSION_MISMATCH_LOGGED = "session_mismatch_logged";

    private final SecurityEventService securityEventService;

    public SessionSecurityFilter(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        // log invalid session ids before continuing
        if (request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid()) {
            securityEventService.logHighSeverityEvent(
                "SESSION_HIJACK_ATTEMPT",
                resolveUsername(),
                "Invalid session identifier presented",
                "ip=" + request.getRemoteAddr()
            );
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            String ip = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");
            Object storedIp = session.getAttribute(SESSION_IP);
            Object storedUa = session.getAttribute(SESSION_UA);
            if (storedIp == null) {
                session.setAttribute(SESSION_IP, ip);
            }
            if (storedUa == null) {
                session.setAttribute(SESSION_UA, userAgent);
            }
            boolean mismatchLogged = Boolean.TRUE.equals(session.getAttribute(SESSION_MISMATCH_LOGGED));
            if (!mismatchLogged && storedIp != null && storedUa != null) {
                boolean ipMismatch = !storedIp.equals(ip);
                boolean uaMismatch = userAgent != null && !storedUa.equals(userAgent);
                if (ipMismatch || uaMismatch) {
                    session.setAttribute(SESSION_MISMATCH_LOGGED, true);
                    securityEventService.logHighSeverityEvent(
                        "SESSION_HIJACK_ATTEMPT",
                        resolveUsername(),
                        "Session context mismatch detected",
                        "ip=" + ip + " | ua=" + userAgent
                    );
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "anonymous";
        }
        return authentication.getName();
    }
}
