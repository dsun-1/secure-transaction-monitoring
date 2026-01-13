package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
// simple in-memory rate limit for hot endpoints
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 5_000L;
    private static final int MAX_REQUESTS = 50;
    private static final ConcurrentHashMap<String, Window> WINDOWS = new ConcurrentHashMap<>();

    private final SecurityEventService securityEventService;

    public RateLimitingFilter(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        // enforce rate limits only on selected paths
        String path = request.getRequestURI();
        if (!shouldRateLimit(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = request.getRemoteAddr() + ":" + rateLimitKey(path);
        long now = System.currentTimeMillis();
        pruneExpiredWindows(now);
        Window window = WINDOWS.compute(key, (k, existing) -> {
            if (existing == null || now - existing.windowStart >= WINDOW_MS) {
                return new Window(now);
            }
            return existing;
        });

        int count = window.count.incrementAndGet();
        if (count > MAX_REQUESTS) {
            response.setStatus(429);
            response.setContentType("text/plain");
            response.getWriter().write("Too Many Requests");
            logRateLimitEvent(request, count);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldRateLimit(String path) {
        return path.startsWith("/products") || path.startsWith("/api/security") || path.startsWith("/register");
    }

    private String rateLimitKey(String path) {
        if (path.startsWith("/api/security")) {
            return "/api/security";
        }
        if (path.startsWith("/register")) {
            return "/register";
        }
        return "/products";
    }

    private void pruneExpiredWindows(long now) {
        WINDOWS.entrySet().removeIf(entry -> now - entry.getValue().windowStart >= WINDOW_MS);
    }

    private static class Window {
        private final long windowStart;
        private final AtomicInteger count = new AtomicInteger(0);

        private Window(long windowStart) {
            this.windowStart = windowStart;
        }
    }

    private void logRateLimitEvent(HttpServletRequest request, int currentCount) {
        securityEventService.logHighSeverityEvent(
            "RATE_LIMIT_EXCEEDED",
            resolveUsername(),
            "Sliding window rate limiting triggered",
            "ip=" + request.getRemoteAddr() + " | path=" + request.getRequestURI() +
                " | count=" + currentCount
        );
    }

    private String resolveUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return "anonymous";
        }
        return auth.getName();
    }
}
