package com.security.monitoring.service;

import com.security.monitoring.model.MonitoringEvent;
import com.security.monitoring.model.ThreatIntelligence;
import com.security.monitoring.repository.MonitoringEventRepository;
import com.security.monitoring.repository.ThreatIntelligenceRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
@Transactional
// correlates raw events into threat intelligence by detecting patterns across layers
public class EventCorrelationService {

    private static final Logger logger = LoggerFactory.getLogger(EventCorrelationService.class);

    private final MonitoringEventRepository eventRepository;
    private final ThreatIntelligenceRepository threatRepository;

    public EventCorrelationService(MonitoringEventRepository eventRepository,
                                   ThreatIntelligenceRepository threatRepository) {
        this.eventRepository = eventRepository;
        this.threatRepository = threatRepository;
    }

    // run correlation every 30 seconds to detect emerging threats
    @Scheduled(fixedDelay = 30_000, initialDelay = 10_000)
    public void correlateEvents() {
        logger.debug("Running event correlation cycle");
        LocalDateTime window = LocalDateTime.now().minusMinutes(30);

        correlateBruteForce(window);
        correlateNetworkThreats(window);
        correlateCredentialStuffing(window);
    }

    // detect brute force: many LOGIN_FAILURE events from the same IP
    private void correlateBruteForce(LocalDateTime since) {
        List<Object[]> hotIps = eventRepository.findSourceIpsExceedingThreshold(
            "LOGIN_FAILURE", since, 5
        );

        for (Object[] row : hotIps) {
            String ip = (String) row[0];
            long count = (long) row[1];

            // mark source events as correlated
            List<MonitoringEvent> events = eventRepository
                .findByEventTypeAndCorrelatedFalseAndReceivedAtAfter("LOGIN_FAILURE", since);

            String correlationId = "BF-" + UUID.randomUUID().toString().substring(0, 8);
            events.stream()
                .filter(e -> ip.equals(e.getSourceIp()))
                .forEach(e -> {
                    e.setCorrelated(true);
                    e.setCorrelationId(correlationId);
                });
            eventRepository.saveAll(events);

            ThreatIntelligence threat = new ThreatIntelligence();
            threat.setThreatType("BRUTE_FORCE_ATTACK");
            threat.setSourceIp(ip);
            threat.setSeverity(count >= 10 ? "CRITICAL" : "HIGH");
            threat.setEventCount((int) count);
            threat.setFirstSeen(since);
            threat.setLastSeen(LocalDateTime.now());
            threat.setIndicators("correlation_id=" + correlationId);
            threat.setRecommendation("Block IP " + ip + ", enforce CAPTCHA, require password reset");
            threatRepository.save(threat);

            logger.info("Correlated brute force attack from IP {} ({} attempts)", ip, count);
        }
    }

    // detect network-layer threats: DNS rebinding, scanning, smuggling
    private void correlateNetworkThreats(LocalDateTime since) {
        List<String> networkTypes = List.of(
            "DNS_REBINDING_ATTEMPT", "REQUEST_SMUGGLING_ATTEMPT",
            "PORT_SCAN_DETECTED", "MALICIOUS_IP_DETECTED",
            "ABNORMAL_TRAFFIC_PATTERN", "PROTOCOL_VIOLATION"
        );

        for (String eventType : networkTypes) {
            List<Object[]> hotIps = eventRepository.findSourceIpsExceedingThreshold(
                eventType, since, 3
            );

            for (Object[] row : hotIps) {
                String ip = (String) row[0];
                long count = (long) row[1];

                String correlationId = "NET-" + UUID.randomUUID().toString().substring(0, 8);
                List<MonitoringEvent> events = eventRepository
                    .findByEventTypeAndCorrelatedFalseAndReceivedAtAfter(eventType, since);
                events.stream()
                    .filter(e -> ip.equals(e.getSourceIp()))
                    .forEach(e -> {
                        e.setCorrelated(true);
                        e.setCorrelationId(correlationId);
                    });
                eventRepository.saveAll(events);

                ThreatIntelligence threat = new ThreatIntelligence();
                threat.setThreatType("NETWORK_" + eventType);
                threat.setSourceIp(ip);
                threat.setSeverity(count >= 10 ? "CRITICAL" : "HIGH");
                threat.setEventCount((int) count);
                threat.setFirstSeen(since);
                threat.setLastSeen(LocalDateTime.now());
                threat.setIndicators("correlation_id=" + correlationId + " | event_type=" + eventType);
                threat.setRecommendation("Block IP at WAF/firewall, analyze traffic pattern for " + eventType);
                threatRepository.save(threat);

                logger.info("Correlated network threat {} from IP {} ({} events)", eventType, ip, count);
            }
        }
    }

    // detect credential stuffing: many LOGIN_FAILURE with different usernames from same IP
    private void correlateCredentialStuffing(LocalDateTime since) {
        List<MonitoringEvent> loginFailures = eventRepository
            .findByEventTypeAndCorrelatedFalseAndReceivedAtAfter("LOGIN_FAILURE", since);

        // group by source IP
        Map<String, List<MonitoringEvent>> byIp = new HashMap<>();
        for (MonitoringEvent e : loginFailures) {
            if (e.getSourceIp() != null) {
                byIp.computeIfAbsent(e.getSourceIp(), k -> new ArrayList<>()).add(e);
            }
        }

        for (Map.Entry<String, List<MonitoringEvent>> entry : byIp.entrySet()) {
            String ip = entry.getKey();
            List<MonitoringEvent> events = entry.getValue();

            // count unique usernames
            Set<String> usernames = new HashSet<>();
            for (MonitoringEvent e : events) {
                if (e.getUsername() != null) {
                    usernames.add(e.getUsername());
                }
            }

            if (usernames.size() >= 4) {
                String correlationId = "CS-" + UUID.randomUUID().toString().substring(0, 8);
                events.forEach(e -> {
                    e.setCorrelated(true);
                    e.setCorrelationId(correlationId);
                });
                eventRepository.saveAll(events);

                ThreatIntelligence threat = new ThreatIntelligence();
                threat.setThreatType("CREDENTIAL_STUFFING_ATTACK");
                threat.setSourceIp(ip);
                threat.setSeverity("CRITICAL");
                threat.setEventCount(events.size());
                threat.setFirstSeen(since);
                threat.setLastSeen(LocalDateTime.now());
                threat.setIndicators("unique_users=" + usernames.size() + " | correlation_id=" + correlationId);
                threat.setRecommendation("Block IP, enable MFA, rotate compromised credentials");
                threatRepository.save(threat);

                logger.info("Correlated credential stuffing from IP {} ({} users, {} attempts)",
                    ip, usernames.size(), events.size());
            }
        }
    }
}
