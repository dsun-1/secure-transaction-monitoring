package com.security.ecommerce.service;

import com.security.ecommerce.model.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
// forwards security events asynchronously to the monitoring microservice via
// REST
public class EventForwardingService {

    private static final Logger logger = LoggerFactory.getLogger(EventForwardingService.class);

    private final RestTemplate restTemplate;
    private final String monitoringUrl;

    public EventForwardingService(RestTemplate monitoringRestTemplate,
            @Qualifier("monitoringServiceUrl") String monitoringServiceUrl) {
        this.restTemplate = monitoringRestTemplate;
        this.monitoringUrl = monitoringServiceUrl;
    }

    // fire-and-forget event forwarding on a separate thread
    @Async
    public void forwardEvent(SecurityEvent event) {
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("eventType",
                    event.getEventType() != null ? event.getEventType().name() : "SUSPICIOUS_ACTIVITY");
            payload.put("username", event.getUsername() != null ? event.getUsername() : "unknown");
            payload.put("sourceIp", event.getIpAddress() != null ? event.getIpAddress() : "");
            payload.put("sessionId", event.getSessionId() != null ? event.getSessionId() : "");
            payload.put("userAgent", event.getUserAgent() != null ? event.getUserAgent() : "");
            payload.put("severity", event.getSeverity() != null ? event.getSeverity().name() : "MEDIUM");
            payload.put("description", event.getDescription() != null ? event.getDescription() : "");
            payload.put("additionalData", event.getAdditionalData() != null ? event.getAdditionalData() : "");
            payload.put("successful", event.isSuccessful());
            payload.put("sourceService", "ecommerce-app");
            payload.put("timestamp",
                    event.getTimestamp() != null ? event.getTimestamp().toString() : LocalDateTime.now().toString());

            restTemplate.postForObject(
                    monitoringUrl + "/api/events/ingest",
                    payload,
                    Map.class);

            logger.debug("Forwarded event {} to monitoring service", event.getEventType());
        } catch (Exception e) {
            // non-critical: log and discard if the monitoring service is unavailable
            logger.debug("Monitoring service unavailable, event not forwarded: {}", e.getMessage());
        }
    }
}
