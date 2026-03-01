package com.security.monitoring.repository;

import com.security.monitoring.model.ThreatIntelligence;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface ThreatIntelligenceRepository extends JpaRepository<ThreatIntelligence, Long> {

    List<ThreatIntelligence> findByEscalatedFalse();

    List<ThreatIntelligence> findBySeverityAndCreatedAtAfter(String severity, LocalDateTime since);

    List<ThreatIntelligence> findBySourceIp(String sourceIp);

    List<ThreatIntelligence> findByThreatType(String threatType);
}
