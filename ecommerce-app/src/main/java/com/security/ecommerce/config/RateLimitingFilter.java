package com.security.ecommerce.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.security.ecommerce.service.SecurityEventService;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Order(Ordered.LOWEST_PRECEDENCE - 10)
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 5_000L;
    private static final int MAX_REQUESTS = 50;
    private static final int MAX_ENTRIES = 1_000;
    private static final ConcurrentHashMap<String, Window> WINDOWS = new ConcurrentHashMap<>();

    private final SecurityEventService securityEventService;

    public RateLimitingFilter(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (!shouldRateLimit(path)) {
            filterChain.doFilter(request, response);
            return;
        }
        if (isAuthenticatedUser()) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = request.getRemoteAddr() + ":" + rateLimitKey(path);
        long now = System.currentTimeMillis();
        Window window = WINDOWS.compute(key, (k, existing) -> {
            if (existing == null || now - existing.windowStart >= WINDOW_MS) {
                return new Window(now);
            }
            return existing;
        });

        // simple cap to prevent unbounded growth of the in-memory map
        enforceMaxEntries();

        int count = window.count.incrementAndGet();
        if (count > MAX_REQUESTS) {
            String username = resolveUsername();
            securityEventService.logHighSeverityEvent(
                "RATE_LIMIT_EXCEEDED",
                username,
                "Rate limit exceeded for " + path,
                "ip=" + request.getRemoteAddr() + " | count=" + count
            );
            response.setStatus(429);
            response.setContentType("text/plain");
            response.getWriter().write("Too Many Requests");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldRateLimit(String path) {
        return path.startsWith("/products") || path.startsWith("/api/security");
    }

    private String rateLimitKey(String path) {
        if (path.startsWith("/api/security")) {
            return "/api/security";
        }
        return "/products";
    }

    private static class Window {
        private final long windowStart;
        private final AtomicInteger count = new AtomicInteger(0);

        private Window(long windowStart) {
            this.windowStart = windowStart;
        }
    }

    private void enforceMaxEntries() {
        if (WINDOWS.size() <= MAX_ENTRIES) {
            return;
        }
        // remove a single arbitrary entry to cap growth; good enough for demo workload
        WINDOWS.keySet().stream().findFirst().ifPresent(WINDOWS::remove);
    }

    private String resolveUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "anonymous";
        }
        return authentication.getName();
    }

    private boolean isAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
            && authentication.isAuthenticated()
            && !(authentication.getPrincipal() instanceof String && "anonymousUser".equals(authentication.getPrincipal()));
    }
}
