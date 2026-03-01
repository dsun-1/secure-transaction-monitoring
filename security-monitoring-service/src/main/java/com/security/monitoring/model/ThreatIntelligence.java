package com.security.monitoring.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "threat_intelligence")
@Data
@NoArgsConstructor
@AllArgsConstructor
// threat intel entries derived from event correlation
public class ThreatIntelligence {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String threatType;

    private String sourceIp;
    private String targetUsername;

    @Column(nullable = false)
    private String severity;

    @Column(length = 2000)
    private String indicators;

    @Column(nullable = false)
    private int eventCount;

    private LocalDateTime firstSeen;
    private LocalDateTime lastSeen;

    @Column(length = 1000)
    private String recommendation;

    // whether a jira ticket was created for this threat
    private boolean escalated = false;
    private String jiraTicketId;

    private LocalDateTime createdAt;

    @PrePersist
    void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
