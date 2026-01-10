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
import org.springframework.beans.factory.annotation.Value;

@Service
@Transactional
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${security.lockout.enabled:true}")
    private boolean lockoutEnabled;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
            .password(user.getPassword())
            .roles(user.getRole())
            .disabled(!user.isActive())
            .accountLocked(user.isAccountLocked()) 
            .build();
    }

    
    public boolean incrementFailedAttempts(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null) {
            boolean wasLocked = !user.isAccountNonLocked();
            if (lockoutEnabled) {
                user.incrementFailedAttempts();
            } else {
                user.setLastFailedLogin(java.time.LocalDateTime.now());
                user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
                user.setAccountNonLocked(true);
                user.setAccountLockedUntil(null);
            }
            userRepository.save(user);
            boolean nowLocked = lockoutEnabled && !user.isAccountNonLocked();
            return !wasLocked && nowLocked;
        }
        return false;
    }

    public void resetFailedAttempts(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null) {
            user.resetFailedAttempts();
            user.setAccountNonLocked(true);
            user.setAccountLockedUntil(null);
            userRepository.save(user);
        }
    }
    

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public User save(@NonNull User user) {
        return userRepository.save(user);
    }
}
