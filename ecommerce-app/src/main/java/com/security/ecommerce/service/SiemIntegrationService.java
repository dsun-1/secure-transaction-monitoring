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
    
    @Value("${jira.enabled:false}")
    private boolean jiraEnabled;
    @Value("${jira.url:}")
    private String jiraUrl;
    @Value("${jira.username:}")
    private String jiraUsername;
    @Value("${jira.apiToken:}")
    private String jiraApiToken;
    @Value("${jira.projectKey:}")
    private String jiraProjectKey;

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
        
        if (jiraEnabled) {
            createJiraTicket(event);
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
    
    private void createJiraTicket(SecurityEvent event) {
        if (!jiraEnabled || jiraUrl.isEmpty() || jiraUsername.isEmpty() || jiraApiToken.isEmpty() || jiraProjectKey.isEmpty()) {
            logger.info("JIRA integration not configured or disabled.");
            return;
        }
        try {
            String json = String.format("{\"fields\":{\"project\":{\"key\":\"%s\"},\"summary\":\"%s\",\"description\":\"%s\",\"issuetype\":{\"name\":\"Task\"}}}",
                jiraProjectKey,
                event.getEventType() + " - " + event.getSeverity(),
                event.getDescription());
            java.net.URL url = new java.net.URL(jiraUrl + "/rest/api/2/issue");
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            String auth = java.util.Base64.getEncoder().encodeToString((jiraUsername + ":" + jiraApiToken).getBytes());
            conn.setRequestProperty("Authorization", "Basic " + auth);
            conn.setDoOutput(true);
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes());
            }
            int responseCode = conn.getResponseCode();
            if (responseCode == 201) {
                logger.info("JIRA ticket created for event: {}", event.getEventType());
            } else {
                logger.warn("Failed to create JIRA ticket. Response code: {}", responseCode);
            }
        } catch (Exception e) {
            logger.error("Error creating JIRA ticket: {}", e.getMessage());
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
