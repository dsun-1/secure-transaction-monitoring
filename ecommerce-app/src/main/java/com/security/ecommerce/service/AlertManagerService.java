package com.security.ecommerce.service;

import com.security.ecommerce.model.SecurityEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.format.DateTimeFormatter;

/**
 * Alert Manager Service
 * Handles real-time alerting for critical security events
 * Supports Slack, Email, and PagerDuty integrations
 */
@Service
public class AlertManagerService {
    
    private static final Logger logger = LoggerFactory.getLogger(AlertManagerService.class);
    
    @Value("${alert.slack.enabled:false}")
    private boolean slackEnabled;
    
    @Value("${alert.email.enabled:false}")
    private boolean emailEnabled;
    
    @Value("${alert.pagerduty.enabled:false}")
    private boolean pagerdutyEnabled;
    
    /**
     * Send alert through all configured channels
     */
    @Async
    public void sendAlert(SecurityEvent event) {
        String alertMessage = formatAlertMessage(event);
        
        if (slackEnabled) {
            sendSlackAlert(alertMessage, event);
        }
        
        if (emailEnabled) {
            sendEmailAlert(alertMessage, event);
        }
        
        if (pagerdutyEnabled) {
            sendPagerDutyAlert(alertMessage, event);
        }
        
        // Always log to console
        logger.warn("🚨 SECURITY ALERT: {} - {} - {}", 
            event.getSeverity(), event.getEventType(), event.getDescription());
    }
    
    private void sendSlackAlert(String message, SecurityEvent event) {
        // TODO: Implement Slack webhook integration
        logger.info("📱 Slack alert would be sent: {}", event.getEventType());
    }
    
    private void sendEmailAlert(String message, SecurityEvent event) {
        // TODO: Implement email sending
        logger.info("📧 Email alert would be sent: {}", event.getEventType());
    }
    
    private void sendPagerDutyAlert(String message, SecurityEvent event) {
        // TODO: Implement PagerDuty integration
        logger.info("📟 PagerDuty alert would be sent: {}", event.getEventType());
    }
    
    private String formatAlertMessage(SecurityEvent event) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        
        return String.format(
            "🚨 SECURITY ALERT\n" +
            "Severity: %s\n" +
            "Event Type: %s\n" +
            "Time: %s\n" +
            "User: %s\n" +
            "IP: %s\n" +
            "Description: %s\n" +
            "Successful: %s",
            event.getSeverity(),
            event.getEventType(),
            event.getTimestamp() != null ? event.getTimestamp().format(formatter) : "N/A",
            event.getUsername() != null ? event.getUsername() : "Anonymous",
            event.getIpAddress() != null ? event.getIpAddress() : "Unknown",
            event.getDescription(),
            event.isSuccessful()
        );
    }
}
