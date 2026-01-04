package com.security.tests.utils;

import java.time.LocalDateTime;


public class SecurityEvent {
    private String eventType;
    private String severity;
    private String username;
    private String sessionId;
    private String ipAddress;
    private String userAgent;
    private String eventDetails;
    private String suspectedThreat;
    private LocalDateTime timestamp;
    
    public SecurityEvent() {
        this.timestamp = LocalDateTime.now();
    }
    
    public static SecurityEvent createHighSeverityEvent(String eventType, String username, 
                                                       String threat, String details) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(eventType);
        event.setSeverity("HIGH");
        event.setUsername(username);
        event.setSuspectedThreat(threat);
        event.setEventDetails(details);
        return event;
    }
    
    public static SecurityEvent createMediumSeverityEvent(String eventType, String username, 
                                                         String threat, String details) {
        SecurityEvent event = new SecurityEvent();
        event.setEventType(eventType);
        event.setSeverity("MEDIUM");
        event.setUsername(username);
        event.setSuspectedThreat(threat);
        event.setEventDetails(details);
        return event;
    }
    
    
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    
    public String getEventDetails() { return eventDetails; }
    public void setEventDetails(String eventDetails) { this.eventDetails = eventDetails; }
    
    public String getSuspectedThreat() { return suspectedThreat; }
    public void setSuspectedThreat(String suspectedThreat) { this.suspectedThreat = suspectedThreat; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}
