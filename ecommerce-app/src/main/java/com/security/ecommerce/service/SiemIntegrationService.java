package com.security.ecommerce.service;

import com.security.ecommerce.model.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * SIEM Integration Service
 * Sends security events to external SIEM systems (Elasticsearch, Splunk)
 */
@Service
public class SiemIntegrationService {
    
    private static final Logger logger = LoggerFactory.getLogger(SiemIntegrationService.class);
    
    @Value("${siem.elasticsearch.enabled:false}")
    private boolean elasticsearchEnabled;
    
    @Value("${siem.elasticsearch.url:http://localhost:9200}")
    private String elasticsearchUrl;
    
    @Value("${siem.elasticsearch.index:security-events}")
    private String elasticsearchIndex;
    
    @Value("${siem.splunk.enabled:false}")
    private boolean splunkEnabled;
    
    @Value("${siem.splunk.url:}")
    private String splunkUrl;
    
    private final AlertManagerService alertManager;
    
    public SiemIntegrationService(AlertManagerService alertManager) {
        this.alertManager = alertManager;
    }
    
    /**
     * Send security event to configured SIEM systems asynchronously
     */
    @Async
    public void sendToSiem(SecurityEvent event) {
        if (elasticsearchEnabled) {
            sendToElasticsearch(event);
        }
        
        if (splunkEnabled) {
            sendToSplunk(event);
        }
        
        // Check if event requires immediate alerting
        if (isHighSeverityEvent(event)) {
            alertManager.sendAlert(event);
        }
    }
    
    private void sendToElasticsearch(SecurityEvent event) {
        try {
            String url = String.format("%s/%s/_doc", elasticsearchUrl, elasticsearchIndex);
            logger.debug("📊 Would send to Elasticsearch: {} - Event: {}", url, event.getEventType());
            // TODO: Implement actual HTTP POST to Elasticsearch
        } catch (Exception e) {
            logger.error("Failed to send event to Elasticsearch: {}", e.getMessage());
        }
    }
    
    private void sendToSplunk(SecurityEvent event) {
        try {
            logger.debug("📊 Would send to Splunk: {} - Event: {}", splunkUrl, event.getEventType());
            // TODO: Implement actual HTTP POST to Splunk HEC
        } catch (Exception e) {
            logger.error("Failed to send event to Splunk: {}", e.getMessage());
        }
    }
    
    /**
     * Determine if event requires immediate alerting
     */
    private boolean isHighSeverityEvent(SecurityEvent event) {
        return event.getSeverity() == SecurityEvent.EventSeverity.CRITICAL 
            || event.getSeverity() == SecurityEvent.EventSeverity.HIGH
            || isSecurityThreat(event.getEventType());
    }
    
    /**
     * Check if event type indicates a security threat
     */
    private boolean isSecurityThreat(SecurityEvent.EventType eventType) {
        return eventType == SecurityEvent.EventType.SQL_INJECTION_ATTEMPT ||
            eventType == SecurityEvent.EventType.XSS_ATTEMPT ||
            eventType == SecurityEvent.EventType.BRUTE_FORCE_DETECTED ||
            eventType == SecurityEvent.EventType.PRIVILEGE_ESCALATION_ATTEMPT ||
            eventType == SecurityEvent.EventType.SESSION_HIJACK_ATTEMPT ||
            eventType == SecurityEvent.EventType.CSRF_VIOLATION;
    }
}
