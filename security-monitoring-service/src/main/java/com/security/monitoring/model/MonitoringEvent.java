package com.security.monitoring.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "monitoring_events", indexes = {
    @Index(name = "idx_event_type", columnList = "eventType"),
    @Index(name = "idx_source_ip", columnList = "sourceIp"),
    @Index(name = "idx_severity", columnList = "severity"),
    @Index(name = "idx_timestamp", columnList = "receivedAt"),
    @Index(name = "idx_layer", columnList = "layer")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
// ingested security event persisted by the monitoring service
public class MonitoringEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String eventType;

    private String username;
    private String sourceIp;
    private String sessionId;
    private String userAgent;

    @Column(nullable = false)
    private String severity;

    @Column(length = 1000)
    private String description;

    @Column(length = 2000)
    private String additionalData;

    private boolean successful;

    // authentication | application | network
    @Column(nullable = false)
    private String layer;

    // origin service that emitted this event
    @Column(nullable = false)
    private String sourceService;

    private LocalDateTime eventTimestamp;

    @Column(nullable = false)
    private LocalDateTime receivedAt;

    // whether the event has been correlated with other events
    private boolean correlated = false;

    // link back to the incident this event was grouped into
    private String correlationId;

    @PrePersist
    void prePersist() {
        if (receivedAt == null) {
            receivedAt = LocalDateTime.now();
        }
    }
}
