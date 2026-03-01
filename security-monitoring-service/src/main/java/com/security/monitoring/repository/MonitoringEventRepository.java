package com.security.monitoring.repository;

import com.security.monitoring.model.MonitoringEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface MonitoringEventRepository extends JpaRepository<MonitoringEvent, Long> {

    List<MonitoringEvent> findByEventTypeAndReceivedAtAfter(String eventType, LocalDateTime since);

    List<MonitoringEvent> findBySeverityAndReceivedAtAfterOrderByReceivedAtDesc(String severity, LocalDateTime since);

    List<MonitoringEvent> findByLayerAndReceivedAtAfter(String layer, LocalDateTime since);

    // count events per source IP within a window for brute force detection
    @Query("""
        SELECT e.sourceIp, COUNT(e) FROM MonitoringEvent e
        WHERE e.eventType = :eventType
          AND e.receivedAt > :since
        GROUP BY e.sourceIp
        HAVING COUNT(e) >= :threshold
    """)
    List<Object[]> findSourceIpsExceedingThreshold(
        @Param("eventType") String eventType,
        @Param("since") LocalDateTime since,
        @Param("threshold") long threshold
    );

    // aggregate event counts by type for dashboard
    @Query("""
        SELECT e.eventType, e.severity, COUNT(e) FROM MonitoringEvent e
        WHERE e.receivedAt > :since
        GROUP BY e.eventType, e.severity
        ORDER BY COUNT(e) DESC
    """)
    List<Object[]> getEventSummary(@Param("since") LocalDateTime since);

    // aggregate event counts by layer
    @Query("""
        SELECT e.layer, COUNT(e) FROM MonitoringEvent e
        WHERE e.receivedAt > :since
        GROUP BY e.layer
    """)
    List<Object[]> getLayerSummary(@Param("since") LocalDateTime since);

    // find uncorrelated events of a given type for correlation engine
    List<MonitoringEvent> findByEventTypeAndCorrelatedFalseAndReceivedAtAfter(
        String eventType, LocalDateTime since
    );
}
