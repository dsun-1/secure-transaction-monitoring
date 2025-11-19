package com.security.ecommerce.config;

import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final SecurityEventService securityEventService;
    private final UserService userService;

    public SecurityConfig(SecurityEventService securityEventService, UserService userService) {
        this.securityEventService = securityEventService;
        this.userService = userService;
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
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
                // FIX: Removed "/api/**" from this list so it defaults to authenticated() below
                .requestMatchers("/", "/login", "/register", "/error", "/h2-console/**", "/css/**", "/js/**", 
                               "/products", "/product/**", "/cart/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // ... rest of the code remains the same ...
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/perform_login")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .sessionManagement(session -> session
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );

        // H2 Console access
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));

        return http.build();
    }
}