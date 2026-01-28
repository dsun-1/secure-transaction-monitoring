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
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
// simple in-memory rate limit for hot endpoints
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 5_000L;
    private static final int MAX_REQUESTS = 50;
    private static final ConcurrentHashMap<String, SlidingWindow> WINDOWS = new ConcurrentHashMap<>();

    private final SecurityEventService securityEventService;
    private final Clock clock;

    @Autowired
    public RateLimitingFilter(SecurityEventService securityEventService) {
        this(securityEventService, Clock.systemUTC());
    }

    RateLimitingFilter(SecurityEventService securityEventService, Clock clock) {
        this.securityEventService = securityEventService;
        this.clock = clock;
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
        long now = clock.millis();
        pruneExpiredWindows(now);
        SlidingWindow window = WINDOWS.computeIfAbsent(key, k -> new SlidingWindow());
        int count = window.addAndCount(now);
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
        WINDOWS.entrySet().removeIf(entry -> entry.getValue().pruneAndIsEmpty(now));
    }

    private static class SlidingWindow {
        private final Deque<Long> timestamps = new ArrayDeque<>();

        private int addAndCount(long now) {
            synchronized (this) {
                prune(now);
                timestamps.addLast(now);
                return timestamps.size();
            }
        }

        private boolean pruneAndIsEmpty(long now) {
            synchronized (this) {
                prune(now);
                return timestamps.isEmpty();
            }
        }

        private void prune(long now) {
            while (!timestamps.isEmpty() && now - timestamps.peekFirst() >= WINDOW_MS) {
                timestamps.pollFirst();
            }
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
