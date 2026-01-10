package com.security.ecommerce.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Username is required")
    @Column(unique = true, nullable = false)
    private String username;

    @NotBlank(message = "Password is required")
    private String password;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Column(unique = true, nullable = false)
    private String email;

    private String role = "USER";

    private boolean accountNonLocked = true;

    private int failedLoginAttempts = 0;

    private LocalDateTime lastFailedLogin;

    private LocalDateTime accountLockedUntil;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    private boolean active = true;

    
    public void incrementFailedAttempts() {
        this.failedLoginAttempts++;
        this.lastFailedLogin = LocalDateTime.now();
        
        
        if (this.failedLoginAttempts >= 5) {
            this.accountNonLocked = false;
            this.accountLockedUntil = LocalDateTime.now().plusMinutes(30);
        }
    }

    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
        this.lastFailedLogin = null;
    }

    public boolean isAccountLocked() {
        if (!accountNonLocked && accountLockedUntil != null) {
            if (LocalDateTime.now().isAfter(accountLockedUntil)) {
                
                this.accountNonLocked = true;
                this.accountLockedUntil = null;
                this.failedLoginAttempts = 0;
                return false;
            }
            return true;
        }
        return false;
    }
}
