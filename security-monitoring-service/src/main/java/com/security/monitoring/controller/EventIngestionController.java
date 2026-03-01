package com.security.monitoring.controller;

import com.security.monitoring.model.MonitoringEvent;
import com.security.monitoring.repository.MonitoringEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/events")
// REST endpoint for receiving security events from upstream microservices
public class EventIngestionController {

    private static final Logger logger = LoggerFactory.getLogger(EventIngestionController.class);

    // event types classified by layer for automatic layer assignment
    private static final Set<String> AUTH_EVENTS = Set.of(
        "LOGIN_ATTEMPT", "LOGIN_SUCCESS", "LOGIN_FAILURE", "LOGOUT",
        "ACCOUNT_LOCKED", "ACCOUNT_ENUMERATION", "BRUTE_FORCE_DETECTED",
        "DISTRIBUTED_BRUTE_FORCE", "CREDENTIAL_STUFFING", "SESSION_HIJACK_ATTEMPT",
        "SESSION_FIXATION_ATTEMPT", "BOT_REGISTRATION_ATTEMPT", "PASSWORD_CHANGE"
    );

    private static final Set<String> NETWORK_EVENTS = Set.of(
        "DNS_REBINDING_ATTEMPT", "REQUEST_SMUGGLING_ATTEMPT", "PORT_SCAN_DETECTED",
        "MALICIOUS_IP_DETECTED", "GEO_ANOMALY_DETECTED", "ABNORMAL_TRAFFIC_PATTERN",
        "TLS_DOWNGRADE_ATTEMPT", "PROTOCOL_VIOLATION", "RATE_LIMIT_EXCEEDED"
    );

    private final MonitoringEventRepository eventRepository;

    public EventIngestionController(MonitoringEventRepository eventRepository) {
        this.eventRepository = eventRepository;
    }

    // ingest a single security event from an upstream service
    @PostMapping("/ingest")
    public ResponseEntity<Map<String, Object>> ingestEvent(@RequestBody EventPayload payload) {
        if (payload.eventType() == null || payload.eventType().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "eventType is required"));
        }

        MonitoringEvent event = new MonitoringEvent();
        event.setEventType(payload.eventType());
        event.setUsername(payload.username());
        event.setSourceIp(payload.sourceIp());
        event.setSessionId(payload.sessionId());
        event.setUserAgent(payload.userAgent());
        event.setSeverity(payload.severity() != null ? payload.severity() : "MEDIUM");
        event.setDescription(payload.description());
        event.setAdditionalData(payload.additionalData());
        event.setSuccessful(payload.successful());
        event.setLayer(resolveLayer(payload.eventType()));
        event.setSourceService(payload.sourceService() != null ? payload.sourceService() : "ecommerce-app");
        event.setEventTimestamp(payload.timestamp() != null ? payload.timestamp() : LocalDateTime.now());

        MonitoringEvent saved = eventRepository.save(event);
        logger.info("Ingested event: {} [{}] from {} (id={})",
            saved.getEventType(), saved.getSeverity(), saved.getSourceService(), saved.getId());

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
            "id", saved.getId(),
            "eventType", saved.getEventType(),
            "layer", saved.getLayer(),
            "receivedAt", saved.getReceivedAt().toString()
        ));
    }

    // batch ingest multiple events in a single request
    @PostMapping("/ingest/batch")
    public ResponseEntity<Map<String, Object>> ingestBatch(@RequestBody List<EventPayload> payloads) {
        int ingested = 0;
        for (EventPayload payload : payloads) {
            if (payload.eventType() != null && !payload.eventType().isBlank()) {
                MonitoringEvent event = new MonitoringEvent();
                event.setEventType(payload.eventType());
                event.setUsername(payload.username());
                event.setSourceIp(payload.sourceIp());
                event.setSessionId(payload.sessionId());
                event.setUserAgent(payload.userAgent());
                event.setSeverity(payload.severity() != null ? payload.severity() : "MEDIUM");
                event.setDescription(payload.description());
                event.setAdditionalData(payload.additionalData());
                event.setSuccessful(payload.successful());
                event.setLayer(resolveLayer(payload.eventType()));
                event.setSourceService(payload.sourceService() != null ? payload.sourceService() : "ecommerce-app");
                event.setEventTimestamp(payload.timestamp() != null ? payload.timestamp() : LocalDateTime.now());
                eventRepository.save(event);
                ingested++;
            }
        }

        logger.info("Batch ingested {} events", ingested);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
            "ingested", ingested,
            "total", payloads.size()
        ));
    }

    // classify event type into its security layer
    private String resolveLayer(String eventType) {
        if (AUTH_EVENTS.contains(eventType)) return "authentication";
        if (NETWORK_EVENTS.contains(eventType)) return "network";
        return "application";
    }

    // immutable payload record for event ingestion
    public record EventPayload(
        String eventType,
        String username,
        String sourceIp,
        String sessionId,
        String userAgent,
        String severity,
        String description,
        String additionalData,
        boolean successful,
        String sourceService,
        LocalDateTime timestamp
    ) {}
}
