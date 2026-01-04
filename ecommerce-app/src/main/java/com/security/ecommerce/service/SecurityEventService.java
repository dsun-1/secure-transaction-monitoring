package com.security.ecommerce.service;

import com.security.ecommerce.model.SecurityEvent;
import com.security.ecommerce.repository.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Transactional
// central logger for security telemetry; feeds the siem analysis pipeline
public class SecurityEventService {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityEventService.class);
    
    @Autowired
    private SecurityEventRepository securityEventRepository;
    
    
    
    
    
    
    // persist any security event and emit a structured audit log entry
    public SecurityEvent logEvent(SecurityEvent event) {
        if (event.getTimestamp() == null) {
            event.setTimestamp(LocalDateTime.now());
        }
        SecurityEvent saved = securityEventRepository.save(event);
        logger.info("Security Event Logged: {} - {} - {}", 
            event.getEventType(), event.getSeverity(), event.getDescription());
        
        
        
        
        
        
        return saved;
    }
    
    // standardizes login success/failure events for auth monitoring
    public SecurityEvent logAuthenticationAttempt(String username, String ipAddress, 
                                                   boolean successful, String userAgent) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(successful ? SecurityEvent.EventType.LOGIN_SUCCESS : 
                                        SecurityEvent.EventType.LOGIN_FAILURE);
        event.setUsername(username);
        event.setIpAddress(ipAddress);
        event.setUserAgent(userAgent);
        event.setSuccessful(successful);
        event.setSeverity(successful ? SecurityEvent.EventSeverity.LOW : 
                                      SecurityEvent.EventSeverity.MEDIUM);
        event.setDescription(successful ? "Successful login" : "Failed login attempt");
        event.setTimestamp(LocalDateTime.now());
        
        return logEvent(event);
    }
    
    // convenience wrapper for high-severity alerts used by tests and detections
    public SecurityEvent logHighSeverityEvent(String eventType, String username, 
                                               String description, String additionalData) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(SecurityEvent.EventType.SUSPICIOUS_ACTIVITY);
        event.setUsername(username);
        event.setSeverity(SecurityEvent.EventSeverity.HIGH);
        event.setDescription(description);
        event.setAdditionalData(additionalData);
        event.setSuccessful(false);
        event.setTimestamp(LocalDateTime.now());
        
        return logEvent(event);
    }
    
    // used by dashboards or siem queries to pull recent critical activity
    public List<SecurityEvent> getRecentHighSeverityEvents(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return securityEventRepository.findHighSeverityEventsSince(since);
    }
    
    // supports brute-force detection by aggregating failed attempts
    public List<SecurityEvent> getFailedLoginsByIp(String ipAddress, int minutes) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(minutes);
        return securityEventRepository.findFailedAttemptsByIpSince(ipAddress, since);
    }
    
    // admin-level view of all security events
    public List<SecurityEvent> getAllEvents() {
        return securityEventRepository.findAll();
    }
}
