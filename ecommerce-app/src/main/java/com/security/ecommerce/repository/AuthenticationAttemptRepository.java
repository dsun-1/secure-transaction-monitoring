package com.security.ecommerce.repository;

import com.security.ecommerce.model.AuthenticationAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuthenticationAttemptRepository extends JpaRepository<AuthenticationAttempt, Long> {
    
    @Query("SELECT a FROM AuthenticationAttempt a WHERE a.success = false AND a.ipAddress = ?1 AND a.attemptTimestamp > ?2")
    List<AuthenticationAttempt> findFailedAttemptsByIpSince(String ipAddress, LocalDateTime since);
    
    @Query("SELECT a FROM AuthenticationAttempt a WHERE a.success = false AND a.username = ?1 AND a.attemptTimestamp > ?2")
    List<AuthenticationAttempt> findFailedAttemptsByUsernameSince(String username, LocalDateTime since);
    
    @Query("SELECT COUNT(a) FROM AuthenticationAttempt a WHERE a.success = false AND a.ipAddress = ?1 AND a.attemptTimestamp > ?2")
    long countFailedAttemptsByIpSince(String ipAddress, LocalDateTime since);
}
