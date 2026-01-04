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

@Configuration
@EnableWebSecurity
// central security policy for auth, sessions, and csrf; this is the primary guardrail for the app
public class SecurityConfig {

    private final SecurityEventService securityEventService;
    private final UserService userService;

    public SecurityConfig(SecurityEventService securityEventService, @Lazy UserService userService) {
        this.securityEventService = securityEventService;
        this.userService = userService;
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
            response.sendRedirect("/checkout");
        };
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            // log failed auth and increment failure counters
            String username = request.getParameter("username");
            String ipAddress = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");
            
            securityEventService.logAuthenticationAttempt(username, ipAddress, false, userAgent);
            
            if (username != null) {
                userService.incrementFailedAttempts(username);
            }

            response.sendRedirect("/login?error=true");
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // define public vs protected routes
                .requestMatchers("/", "/login", "/register", "/error", "/h2-console/**", "/css/**", "/js/**", 
                               "/products", "/cart/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
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
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/h2-console/**")
            )
            .sessionManagement(session -> session
                // limit concurrent sessions per user
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );

        // h2 console uses frames in dev; disable frame options to keep console usable
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

        return http.build();
    }
}
