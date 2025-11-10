package com.security.ecommerce.repository;

import com.security.ecommerce.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {
    
    List<SecurityEvent> findByEventType(SecurityEvent.EventType eventType);
    
    List<SecurityEvent> findBySeverity(SecurityEvent.EventSeverity severity);
    
    List<SecurityEvent> findByUsernameAndTimestampAfter(String username, LocalDateTime timestamp);
    
    @Query("SELECT e FROM SecurityEvent e WHERE e.severity = 'HIGH' AND e.timestamp > ?1")
    List<SecurityEvent> findHighSeverityEventsSince(LocalDateTime timestamp);
    
    @Query("SELECT e FROM SecurityEvent e WHERE e.ipAddress = ?1 AND e.successful = false AND e.timestamp > ?2")
    List<SecurityEvent> findFailedAttemptsByIpSince(String ipAddress, LocalDateTime timestamp);
}
