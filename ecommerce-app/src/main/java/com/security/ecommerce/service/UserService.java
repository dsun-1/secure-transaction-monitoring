package com.security.ecommerce.service;

import com.security.ecommerce.model.User;
import com.security.ecommerce.repository.UserRepository;
import org.springframework.lang.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.regex.Pattern;

@Service
@Transactional
// user lookup and account lock tracking
public class UserService implements UserDetailsService {

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$"
    );
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            User lockedUser = userRepository.findByUsername(username).orElse(null);
            if (lockedUser != null && lockedUser.isAccountLocked()) {
                throw new UsernameNotFoundException("User account is locked");
            }
            
            throw new UsernameNotFoundException("User not found: " + username);
        }
        // map domain user to spring security user details
        org.springframework.security.core.userdetails.User.UserBuilder builder =
            org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
            .password(user.getPassword())
            .disabled(!user.isActive())
            .accountLocked(user.isAccountLocked()) 
            ;

        String role = user.getRole();
        if (role != null && role.startsWith("ROLE_")) {
            return builder.authorities(role).build();
        }
        return builder.roles(role != null ? role : "USER").build();
    }

    // track failed login attempts and lockout thresholds
    public boolean incrementFailedAttempts(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null) {
            boolean wasLocked = user.isAccountLocked();
            user.incrementFailedAttempts();
            userRepository.save(user);
            return !wasLocked && user.isAccountLocked();
        }
        return false;
    }

    public void resetFailedAttempts(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null) {
            user.resetFailedAttempts();
            userRepository.save(user);
        }
    }
    // lookup helpers for controllers and services
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public User registerUser(String username, String email, String password) {
        String normalizedUsername = username == null ? null : username.trim();
        String normalizedEmail = email == null ? null : email.trim();
        validateRegistration(normalizedUsername, normalizedEmail, password);
        if (userRepository.existsByUsername(normalizedUsername)) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException("Email already exists");
        }
        User user = new User();
        user.setUsername(normalizedUsername);
        user.setEmail(normalizedEmail);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("USER");
        user.setActive(true);
        
        return userRepository.save(user);
    }

    public User save(@NonNull User user) {
        return userRepository.save(user);
    }

    private void validateRegistration(String username, String email, String password) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username is required");
        }
        if (email == null || email.isBlank() || !EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException("Valid email is required");
        }
        if (password == null || !PASSWORD_PATTERN.matcher(password).matches()) {
            throw new IllegalArgumentException("Password does not meet complexity requirements");
        }
    }
}
