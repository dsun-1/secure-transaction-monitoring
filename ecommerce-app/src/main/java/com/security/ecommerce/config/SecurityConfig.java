package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
// security policy for auth, sessions, and csrf
public class SecurityConfig {

    private final SecurityEventService securityEventService;
    private final UserService userService;
    private final SecurityAccessDeniedHandler securityAccessDeniedHandler;
    private final ApiAuthEntryPoint apiAuthEntryPoint;
    private final CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
    private final boolean demoMode;
    private final boolean requireHttps;

    public SecurityConfig(SecurityEventService securityEventService,
                          @Lazy UserService userService,
                          SecurityAccessDeniedHandler securityAccessDeniedHandler,
                          ApiAuthEntryPoint apiAuthEntryPoint,
                          @Value("${security.demo-mode:false}") boolean demoMode,
                          @Value("${security.require-https:false}") boolean requireHttps,
                          @Value("${security.cookies.secure:false}") boolean secureCookies) {
        this.securityEventService = securityEventService;
        this.userService = userService;
        this.securityAccessDeniedHandler = securityAccessDeniedHandler;
        this.apiAuthEntryPoint = apiAuthEntryPoint;
        this.demoMode = demoMode;
        this.requireHttps = requireHttps;
        this.csrfTokenRepository.setCookieHttpOnly(true);
        this.csrfTokenRepository.setCookiePath("/");
        this.csrfTokenRepository.setSecure(secureCookies);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            // on login success, log and bind session context
            String username = authentication.getName();
            String ipAddress = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");
            securityEventService.logAuthenticationAttempt(username, ipAddress, true, userAgent);
            userService.resetFailedAttempts(username);
            String requestedSessionId = request.getRequestedSessionId();
            HttpSession session = request.getSession(false);
            String newSessionId = session != null ? session.getId() : null;
            String description;
            if (requestedSessionId == null) {
                description = "No session ID supplied before authentication";
            } else if (requestedSessionId.equals(newSessionId)) {
                description = "Session ID did not rotate after authentication";
            } else {
                description = "Session ID rotated after authentication";
            }
            securityEventService.logHighSeverityEvent(
                "SESSION_FIXATION_ATTEMPT",
                username,
                description,
                "old=" + requestedSessionId + " | new=" + newSessionId
            );
            if (session != null) {
                session.setAttribute("session_ip", ipAddress);
                session.setAttribute("session_user_agent", userAgent);
            }
            CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
            if (csrfToken == null) {
                csrfToken = csrfTokenRepository.generateToken(request);
            }
            csrfTokenRepository.saveToken(csrfToken, request, response);
            response.sendRedirect("/products");
        };

    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            // on login failure, log and update counters
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            String ipAddress = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");
            
            // inspect login inputs for obvious attack patterns
            if (username != null) {
                String usernameLower = username.toLowerCase();
                if (usernameLower.contains("'") || usernameLower.contains("--") || 
                    usernameLower.contains("union") || usernameLower.contains("select") ||
                    usernameLower.contains("or 1=1") || usernameLower.contains("or '1'='1")) {
                    securityEventService.logHighSeverityEvent(
                        "SQL_INJECTION_ATTEMPT",
                        username,
                        "SQL injection pattern detected in login username",
                        "username=" + username + " | ip=" + ipAddress
                    );
                }
                
                if (username.contains("<script") || username.contains("javascript:") ||
                    username.contains("onerror") || username.contains("alert(")) {
                    securityEventService.logHighSeverityEvent(
                        "XSS_ATTEMPT",
                        username,
                        "XSS pattern detected in login username",
                        "username=" + username + " | ip=" + ipAddress
                    );
                }
            }
            
            if (password != null) {
                String passwordLower = password.toLowerCase();
                if (passwordLower.contains("<script") || passwordLower.contains("javascript:") ||
                    passwordLower.contains("onerror") || passwordLower.contains("alert(")) {
                    securityEventService.logHighSeverityEvent(
                        "XSS_ATTEMPT",
                        username != null ? username : "unknown",
                        "XSS pattern detected in login password field",
                        "ip=" + ipAddress
                    );
                }
            }
            
            securityEventService.logAuthenticationAttempt(username, ipAddress, false, userAgent);
            
            if (username != null) {
                boolean lockedNow = userService.incrementFailedAttempts(username);
                if (lockedNow) {
                    securityEventService.logHighSeverityEvent(
                        "BRUTE_FORCE_DETECTED",
                        username,
                        "Account locked after repeated failed logins",
                        "ip=" + ipAddress
                    );
                }
            }

            response.sendRedirect("/login?error=true");
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        if (requireHttps && !demoMode) {
            http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
        }

        http
            .authorizeHttpRequests(auth -> {
                // public routes, admin api, and default auth
                auth.requestMatchers("/", "/login", "/register", "/error", "/css/**", "/js/**",
                    "/products", "/cart/**").permitAll();
                auth.requestMatchers("/api/security/**").hasRole("ADMIN");
                if (demoMode) {
                    auth.requestMatchers("/h2-console/**").permitAll();
                } else {
                    auth.requestMatchers("/h2-console/**").denyAll();
                }
                auth.anyRequest().authenticated();
            })
            
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .permitAll()
            )
            .logout(logout -> logout
                // invalidate session and clear cookie
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .csrf(csrf -> csrf
                // csrf settings for forms and demo console
                .csrfTokenRepository(csrfTokenRepository)
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .sessionManagement(session -> session
                // single session per user
                .sessionFixation(sessionFixation -> sessionFixation.migrateSession())
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );
        if (demoMode) {
            http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
        }

        // apply default security headers
        http.headers(headers -> {
            headers.contentTypeOptions(contentTypeOptions -> {});
            headers.xssProtection(xss -> {});
            headers.cacheControl(cache -> {});
            if (demoMode) {
                headers.frameOptions(frameOptions -> frameOptions.sameOrigin());
            } else {
                headers.frameOptions(frameOptions -> frameOptions.deny());
            }
            headers.referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN));
            headers.permissionsPolicy(permissions -> permissions.policy("geolocation=(), microphone=(), camera=(), payment=()"));
            String cspDirectives = demoMode
                ? "default-src 'self'; " +
                  "script-src 'self' 'unsafe-inline'; " +
                  "style-src 'self' 'unsafe-inline'; " +
                  "img-src 'self' data:; " +
                  "object-src 'none'; " +
                  "base-uri 'self'; " +
                  "form-action 'self'; " +
                  "frame-ancestors 'self'"
                : "default-src 'self'; " +
                  "script-src 'self'; " +
                  "style-src 'self' 'unsafe-inline'; " +
                  "img-src 'self' data:; " +
                  "object-src 'none'; " +
                  "base-uri 'self'; " +
                  "form-action 'self'; " +
                  "frame-ancestors 'self'";
            headers.contentSecurityPolicy(csp -> csp.policyDirectives(cspDirectives));
            headers.httpStrictTransportSecurity(hsts -> hsts
                .includeSubDomains(true)
                .preload(true)
                .maxAgeInSeconds(31536000));
        });

        // map auth failures and access denials to handlers
        http.exceptionHandling(exceptionHandling -> exceptionHandling
            .accessDeniedHandler(securityAccessDeniedHandler)
            .defaultAuthenticationEntryPointFor(apiAuthEntryPoint,
                request -> request.getRequestURI().startsWith("/api/security/"))
        );

        return http.build();
    }

}
