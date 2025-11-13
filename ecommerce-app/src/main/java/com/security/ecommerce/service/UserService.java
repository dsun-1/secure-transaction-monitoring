package com.security.ecommerce.service;

import com.security.ecommerce.model.User;
import com.security.ecommerce.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            // --- FIX: Check for locked account ---
            User lockedUser = userRepository.findByUsername(username).orElse(null);
            if (lockedUser != null && lockedUser.isAccountLocked()) {
                throw new UsernameNotFoundException("User account is locked");
            }
            // ---
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
            .password(user.getPassword())
            .roles(user.getRole())
            .disabled(!user.isActive())
            .accountLocked(user.isAccountLocked()) // <-- Pass lock status to Spring Security
            .build();
    }

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // --- FIX: Added method to handle failed login attempts ---
    public void incrementFailedAttempts(String username) {
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null) {
            user.incrementFailedAttempts();
            userRepository.save(user);
        }
    }
    // ---

    public User authenticate(String username, String password) {
        User user = userRepository.findByUsername(username).orElse(null);
        
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            return user;
        }
        
        return null;
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    public User registerUser(String username, String email, String password) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("USER");
        user.setActive(true);
        
        return userRepository.save(user);
    }

    public User save(User user) {
        return userRepository.save(user);
    }
}