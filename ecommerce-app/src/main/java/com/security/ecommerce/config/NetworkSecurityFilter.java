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
import java.time.Duration;
import java.util.Deque;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.regex.Pattern;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
// detects network-layer anomalies: DNS rebinding, request smuggling, port
// scanning, and suspicious IPs
public class NetworkSecurityFilter extends OncePerRequestFilter {

    private static final Duration SCAN_WINDOW = Duration.ofSeconds(30);
    private static final int SCAN_THRESHOLD = 15;

    // RFC-1918 private ranges and loopback used to detect internal probing
    private static final Pattern PRIVATE_IP_PATTERN = Pattern.compile(
            "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|0\\.0\\.0\\.0|::1|fc00:|fd00:)");

    // cloud metadata endpoints commonly used in SSRF and DNS rebinding
    private static final Set<String> METADATA_HOSTS = Set.of(
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.goog");

    // known malicious or scanner user-agent fragments
    private static final Pattern SCANNER_UA_PATTERN = Pattern.compile(
            "(?i)(nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|wfuzz|nuclei|acunetix|nessus|burp)");

    private final SecurityEventService securityEventService;

    // per-IP sliding window of request timestamps for port-scan / rapid-enumeration
    // detection
    private final ConcurrentHashMap<String, Deque<Long>> requestTimestamps = new ConcurrentHashMap<>();

    public NetworkSecurityFilter(SecurityEventService securityEventService) {
        this.securityEventService = securityEventService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String ip = request.getRemoteAddr();
        String host = request.getHeader("Host");
        String forwardedFor = request.getHeader("X-Forwarded-For");
        String userAgent = request.getHeader("User-Agent");
        String contentLength = request.getHeader("Content-Length");
        String transferEncoding = request.getHeader("Transfer-Encoding");

        // --- DNS rebinding detection ---
        // a legitimate browser sends a Host header matching the server; a mismatch
        // indicates potential DNS rebinding or host header injection
        if (host != null) {
            detectDnsRebinding(request, host, ip);
        }

        // --- HTTP request smuggling indicators ---
        // smuggling attacks rely on ambiguous Content-Length / Transfer-Encoding combos
        detectRequestSmuggling(request, contentLength, transferEncoding, ip);

        // --- port scan / rapid endpoint enumeration ---
        detectPortScanning(request, ip);

        // --- malicious IP / scanner detection ---
        detectMaliciousSource(request, ip, forwardedFor, userAgent);

        // --- protocol violations ---
        detectProtocolViolations(request, ip);

        filterChain.doFilter(request, response);
    }

    // -------------------- DNS Rebinding --------------------

    private void detectDnsRebinding(HttpServletRequest request, String host, String ip) {
        // strip port portion
        String hostOnly = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;

        // flag when the Host header points at a cloud metadata endpoint
        if (METADATA_HOSTS.contains(hostOnly.toLowerCase())) {
            logNetworkEvent("DNS_REBINDING_ATTEMPT", request, ip,
                    "Host header targets cloud metadata endpoint",
                    "host=" + host);
            return;
        }

        // flag private/internal IP addresses in the Host header
        if (PRIVATE_IP_PATTERN.matcher(hostOnly).find()
                && !"localhost".equalsIgnoreCase(hostOnly)
                && !"127.0.0.1".equals(hostOnly)) {
            logNetworkEvent("DNS_REBINDING_ATTEMPT", request, ip,
                    "Host header contains private network address",
                    "host=" + host);
        }
    }

    // -------------------- Request Smuggling -----------------

    private void detectRequestSmuggling(HttpServletRequest request,
            String contentLength, String transferEncoding, String ip) {
        // CL + TE conflict is the classic smuggling vector
        if (contentLength != null && transferEncoding != null) {
            logNetworkEvent("REQUEST_SMUGGLING_ATTEMPT", request, ip,
                    "Conflicting Content-Length and Transfer-Encoding headers",
                    "CL=" + contentLength + " | TE=" + transferEncoding);
            return;
        }

        // chunked transfer-encoding on a non-POST/PUT is suspicious
        if (transferEncoding != null
                && transferEncoding.toLowerCase().contains("chunked")
                && !"POST".equalsIgnoreCase(request.getMethod())
                && !"PUT".equalsIgnoreCase(request.getMethod())) {
            logNetworkEvent("REQUEST_SMUGGLING_ATTEMPT", request, ip,
                    "Chunked encoding on unexpected HTTP method",
                    "method=" + request.getMethod() + " | TE=" + transferEncoding);
        }

        // negative or absurdly large Content-Length
        if (contentLength != null) {
            try {
                long cl = Long.parseLong(contentLength.trim());
                if (cl < 0 || cl > 100_000_000) {
                    logNetworkEvent("REQUEST_SMUGGLING_ATTEMPT", request, ip,
                            "Abnormal Content-Length value",
                            "CL=" + cl);
                }
            } catch (NumberFormatException ignored) {
                logNetworkEvent("PROTOCOL_VIOLATION", request, ip,
                        "Non-numeric Content-Length header",
                        "CL=" + contentLength);
            }
        }
    }

    // -------------------- Port Scanning / Rapid Enumeration ----------

    private void detectPortScanning(HttpServletRequest request, String ip) {
        long now = System.currentTimeMillis();
        Deque<Long> timestamps = requestTimestamps.computeIfAbsent(ip, k -> new ConcurrentLinkedDeque<>());

        // prune old entries outside the window
        long cutoff = now - SCAN_WINDOW.toMillis();
        while (!timestamps.isEmpty()) {
            Long first = timestamps.peekFirst();
            if (first != null && first < cutoff) {
                timestamps.pollFirst();
            } else {
                break;
            }
        }

        timestamps.addLast(now);

        if (timestamps.size() > SCAN_THRESHOLD) {
            logNetworkEvent("PORT_SCAN_DETECTED", request, ip,
                    "Rapid endpoint enumeration detected",
                    "requests_in_window=" + timestamps.size()
                            + " | window_seconds=" + SCAN_WINDOW.getSeconds()
                            + " | path=" + request.getRequestURI());
            // reset to avoid flooding
            timestamps.clear();
        }

        // periodic cleanup of stale IPs
        if (requestTimestamps.size() > 10_000) {
            requestTimestamps.entrySet().removeIf(e -> e.getValue().isEmpty());
        }
    }

    // -------------------- Malicious IP / Scanner Detection ----------

    private void detectMaliciousSource(HttpServletRequest request, String ip,
            String forwardedFor, String userAgent) {
        // detect scanner user agents
        if (userAgent != null && SCANNER_UA_PATTERN.matcher(userAgent).find()) {
            logNetworkEvent("MALICIOUS_IP_DETECTED", request, ip,
                    "Known security scanner user-agent detected",
                    "ua=" + truncate(userAgent, 120));
        }

        // detect spoofed X-Forwarded-For with internal IPs (bypass attempts)
        if (forwardedFor != null) {
            String[] ips = forwardedFor.split(",");
            for (String forwardedIp : ips) {
                String trimmed = forwardedIp.trim();
                if (PRIVATE_IP_PATTERN.matcher(trimmed).find()
                        && !"127.0.0.1".equals(trimmed)
                        && !"0:0:0:0:0:0:0:1".equals(trimmed)) {
                    logNetworkEvent("MALICIOUS_IP_DETECTED", request, ip,
                            "X-Forwarded-For contains private network address",
                            "xff=" + forwardedFor);
                    break;
                }
            }
        }
    }

    // -------------------- Protocol Violations ----------

    private void detectProtocolViolations(HttpServletRequest request, String ip) {
        String method = request.getMethod();

        // TRACE and TRACK are commonly abused for XST attacks
        if ("TRACE".equalsIgnoreCase(method) || "TRACK".equalsIgnoreCase(method)) {
            logNetworkEvent("PROTOCOL_VIOLATION", request, ip,
                    "Dangerous HTTP method used",
                    "method=" + method);
        }

        // oversized query string may indicate buffer overflow or fuzzing attempts
        String queryString = request.getQueryString();
        if (queryString != null && queryString.length() > 4096) {
            logNetworkEvent("ABNORMAL_TRAFFIC_PATTERN", request, ip,
                    "Oversized query string detected",
                    "query_length=" + queryString.length());
        }

        // excessive number of headers may indicate reconnaissance or smuggling
        int headerCount = 0;
        var headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            headerNames.nextElement();
            headerCount++;
        }
        if (headerCount > 50) {
            logNetworkEvent("ABNORMAL_TRAFFIC_PATTERN", request, ip,
                    "Excessive HTTP headers detected",
                    "header_count=" + headerCount);
        }
    }

    // -------------------- Helpers ----------

    private void logNetworkEvent(String eventType, HttpServletRequest request,
            String ip, String description, String additional) {
        String fullAdditional = "ip=" + ip
                + " | path=" + request.getRequestURI()
                + " | method=" + request.getMethod()
                + " | " + additional;
        securityEventService.logHighSeverityEvent(eventType, resolveUsername(), description, fullAdditional);
    }

    private String resolveUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return "anonymous";
        }
        return auth.getName();
    }

    private static String truncate(String value, int max) {
        if (value == null)
            return "";
        return value.length() > max ? value.substring(0, max) + "..." : value;
    }
}
