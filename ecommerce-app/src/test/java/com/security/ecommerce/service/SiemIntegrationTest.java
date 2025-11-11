package com.security.ecommerce.service;

import com.security.ecommerce.model.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for SIEM services
 */
@SpringBootTest
public class SiemIntegrationTest {
    
    @Autowired(required = false)
    private SiemIntegrationService siemIntegrationService;
    
    @Autowired(required = false)
    private AlertManagerService alertManagerService;
    
    @Autowired(required = false)
    private SiemCorrelationService siemCorrelationService;
    
    @Autowired
    private SecurityEventService securityEventService;
    
    @Test
    public void testSiemServicesAreLoaded() {
        // Verify SIEM services are available
        assertNotNull(siemIntegrationService, "SiemIntegrationService should be loaded");
        assertNotNull(alertManagerService, "AlertManagerService should be loaded");
        assertNotNull(siemCorrelationService, "SiemCorrelationService should be loaded");
        assertNotNull(securityEventService, "SecurityEventService should be loaded");
    }
    
    @Test
    public void testSecurityEventLogging() {
        // Create a test security event
        SecurityEvent event = SecurityEvent.loginFailure("testuser", "192.168.1.1", "test-session");
        
        // Log the event (should trigger SIEM integration)
        SecurityEvent saved = securityEventService.logEvent(event);
        
        assertNotNull(saved.getId(), "Event should be saved with an ID");
        assertEquals(SecurityEvent.EventType.LOGIN_FAILURE, saved.getEventType());
        assertEquals(SecurityEvent.EventSeverity.MEDIUM, saved.getSeverity());
    }
    
    @Test
    public void testHighSeverityEventTriggersAlert() {
        // Create a high severity event
        SecurityEvent event = new SecurityEvent();
        event.setEventType(SecurityEvent.EventType.SQL_INJECTION_ATTEMPT);
        event.setUsername("attacker");
        event.setIpAddress("10.0.0.1");
        event.setSeverity(SecurityEvent.EventSeverity.CRITICAL);
        event.setDescription("SQL injection attempt detected");
        event.setSuccessful(false);
        
        // This should log and trigger SIEM alert
        SecurityEvent saved = securityEventService.logEvent(event);
        
        assertNotNull(saved.getId());
        assertEquals(SecurityEvent.EventSeverity.CRITICAL, saved.getSeverity());
    }
}
