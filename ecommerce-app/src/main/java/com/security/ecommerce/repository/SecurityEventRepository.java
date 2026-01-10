package com.security.ecommerce.repository;

import com.security.ecommerce.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {
    @Query("SELECT e FROM SecurityEvent e WHERE e.severity = 'HIGH' AND e.timestamp > ?1")
    List<SecurityEvent> findHighSeverityEventsSince(LocalDateTime timestamp);
}
