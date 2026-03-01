package com.security.monitoring.service;

import com.security.monitoring.model.ThreatIntelligence;
import com.security.monitoring.repository.ThreatIntelligenceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
// generates alerts for un-escalated threats and manages jira integration state
public class AlertService {

    private static final Logger logger = LoggerFactory.getLogger(AlertService.class);

    private final ThreatIntelligenceRepository threatRepository;

    public AlertService(ThreatIntelligenceRepository threatRepository) {
        this.threatRepository = threatRepository;
    }

    // check for un-escalated threats every minute
    @Scheduled(fixedDelay = 60_000, initialDelay = 15_000)
    public void checkForAlerts() {
        List<ThreatIntelligence> pending = threatRepository.findByEscalatedFalse();
        for (ThreatIntelligence threat : pending) {
            if ("CRITICAL".equals(threat.getSeverity()) || "HIGH".equals(threat.getSeverity())) {
                logger.warn("ALERT: {} threat from IP {} — {} events ({})",
                    threat.getThreatType(),
                    threat.getSourceIp(),
                    threat.getEventCount(),
                    threat.getSeverity()
                );
                // in production this would call the jira ticket generator
                // for now, mark it as escalated to avoid duplicate alerts
                threat.setEscalated(true);
                threatRepository.save(threat);
            }
        }
    }

    public void markEscalated(Long threatId, String jiraTicketId) {
        ThreatIntelligence threat = threatRepository.findById(threatId).orElse(null);
        if (threat != null) {
            threat.setEscalated(true);
            threat.setJiraTicketId(jiraTicketId);
            threatRepository.save(threat);
            logger.info("Threat {} escalated to JIRA ticket {}", threatId, jiraTicketId);
        }
    }
}
