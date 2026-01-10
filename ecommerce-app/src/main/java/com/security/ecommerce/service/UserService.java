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

@Service
@Transactional
public class UserService implements UserDetailsService {

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
    

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
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

    public User save(@NonNull User user) {
        return userRepository.save(user);
    }
}
