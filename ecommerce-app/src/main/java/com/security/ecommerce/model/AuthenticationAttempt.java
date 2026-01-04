package com.security.ecommerce.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Entity
@Table(name = "authentication_attempts")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationAttempt {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    
    private String ipAddress;
    
    private boolean success;
    
    private LocalDateTime attemptTimestamp = LocalDateTime.now();
    
    private String userAgent;
    
    private String failureReason;
    
    private String sessionId;
}
