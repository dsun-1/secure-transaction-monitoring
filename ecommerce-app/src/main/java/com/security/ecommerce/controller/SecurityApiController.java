package com.security.ecommerce.controller;

import com.security.ecommerce.model.SecurityEvent;
import com.security.ecommerce.model.Transaction;
import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.TransactionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST API for security monitoring and incident reporting
 * Used by Python scripts and CI/CD pipeline
 */
@RestController
@RequestMapping("/api/security")
public class SecurityApiController {
    
    @Autowired
    private SecurityEventService securityEventService;
    
    @Autowired
    private TransactionService transactionService;
    
    @GetMapping("/events")
    public List<SecurityEvent> getAllSecurityEvents() {
        return securityEventService.getAllEvents();
    }
    
    @GetMapping("/events/high-severity")
    public List<SecurityEvent> getHighSeverityEvents(@RequestParam(defaultValue = "24") int hours) {
        return securityEventService.getRecentHighSeverityEvents(hours);
    }
    
    @GetMapping("/transactions/anomalies")
    public List<Transaction> getAnomalousTransactions() {
        return transactionService.getAnomalousTransactions();
    }
    
    @GetMapping("/transactions/failed")
    public List<Transaction> getFailedTransactions(@RequestParam(defaultValue = "24") int hours) {
        return transactionService.getRecentFailedTransactions(hours);
    }
    
    @GetMapping("/dashboard")
    public Map<String, Object> getDashboard() {
        Map<String, Object> dashboard = new HashMap<>();
        
        List<SecurityEvent> highSeverityEvents = securityEventService.getRecentHighSeverityEvents(24);
        List<Transaction> anomalousTransactions = transactionService.getAnomalousTransactions();
        List<Transaction> failedTransactions = transactionService.getRecentFailedTransactions(24);
        
        dashboard.put("high_severity_events_count", highSeverityEvents.size());
        dashboard.put("anomalous_transactions_count", anomalousTransactions.size());
        dashboard.put("failed_transactions_count", failedTransactions.size());
        dashboard.put("high_severity_events", highSeverityEvents);
        dashboard.put("recent_anomalies", anomalousTransactions);
        dashboard.put("status", highSeverityEvents.isEmpty() ? "HEALTHY" : "ALERT");
        
        return dashboard;
    }
    
    @PostMapping("/test-event")
    public SecurityEvent createTestEvent(@RequestBody Map<String, String> payload) {
        return securityEventService.logHighSeverityEvent(
            payload.getOrDefault("type", "TEST_EVENT"),
            payload.getOrDefault("username", "test"),
            payload.getOrDefault("description", "Test security event"),
            payload.getOrDefault("additionalData", "Test data")
        );
    }
}
