package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.UserService;
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

import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
// central security policy for auth, sessions, and csrf; this is the primary guardrail for the app
public class SecurityConfig {

    private final SecurityEventService securityEventService;
    private final UserService userService;
    private final SecurityAccessDeniedHandler securityAccessDeniedHandler;
    private final ApiAuthEntryPoint apiAuthEntryPoint;
    private final CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();

    public SecurityConfig(SecurityEventService securityEventService,
                          @Lazy UserService userService,
                          SecurityAccessDeniedHandler securityAccessDeniedHandler,
                          ApiAuthEntryPoint apiAuthEntryPoint) {
        this.securityEventService = securityEventService;
        this.userService = userService;
        this.securityAccessDeniedHandler = securityAccessDeniedHandler;
        this.apiAuthEntryPoint = apiAuthEntryPoint;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            // log successful auth for siem pipeline
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
            // log failed auth and increment failure counters
            String username = request.getParameter("username");
            String password = request.getParameter("password");
            String ipAddress = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");
            
            // Detect SQL injection attempts in login form
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
                
                // Detect XSS attempts in login form
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
        http
            .authorizeHttpRequests(auth -> auth
                // define public vs protected routes
                .requestMatchers("/", "/login", "/error", "/h2-console/**", "/css/**", "/js/**",
                               "/products", "/cart/**").permitAll()
                .requestMatchers("/api/security/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .permitAll()
            )
            .logout(logout -> logout
                // invalidate server session and clear cookie
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .csrf(csrf -> csrf
                // use cookie token for ui forms; allow h2 console in dev
                .csrfTokenRepository(csrfTokenRepository)
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                .ignoringRequestMatchers("/h2-console/**")
            )
            .sessionManagement(session -> session
                // limit concurrent sessions per user
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );

        // configure security headers - frameOptions allows H2 console in demo mode
        http.headers(headers -> headers
            .contentTypeOptions(contentTypeOptions -> {})  // defaults to nosniff
            .xssProtection(xss -> {})  // defaults to enabled
            .cacheControl(cache -> {})  // defaults to enabled
            .frameOptions(frameOptions -> frameOptions.sameOrigin())  // allow same-origin framing for H2
        );

        http.exceptionHandling(exceptionHandling -> exceptionHandling
            .accessDeniedHandler(securityAccessDeniedHandler)
            .defaultAuthenticationEntryPointFor(apiAuthEntryPoint,
                new org.springframework.security.web.util.matcher.AntPathRequestMatcher("/api/security/**"))
        );

        return http.build();
    }

}
