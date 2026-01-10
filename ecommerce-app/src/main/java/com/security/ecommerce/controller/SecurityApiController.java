package com.security.ecommerce.controller;

import com.security.ecommerce.model.SecurityEvent;
import com.security.ecommerce.model.Transaction;
import java.math.BigDecimal;
import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.TransactionService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/api/security")
public class SecurityApiController {
    
    private final SecurityEventService securityEventService;
    private final TransactionService transactionService;

    public SecurityApiController(SecurityEventService securityEventService,
                                 TransactionService transactionService) {
        this.securityEventService = securityEventService;
        this.transactionService = transactionService;
    }
    
    @GetMapping("/events")
    public List<SecurityEvent> getAllSecurityEvents() {
        return securityEventService.getAllEvents();
    }
    
    @GetMapping("/events/high-severity")
    public List<SecurityEvent> getHighSeverityEvents(@RequestParam(defaultValue = "24") int hours) {
        return securityEventService.getRecentHighSeverityEvents(hours);
    }
    
    @GetMapping("/transactions/anomalies")
    public List<TransactionSummary> getAnomalousTransactions() {
        return transactionService.getAnomalousTransactions()
            .stream()
            .map(this::toSummary)
            .collect(Collectors.toList());
    }
    
    @GetMapping("/transactions/failed")
    public List<TransactionSummary> getFailedTransactions(@RequestParam(defaultValue = "24") int hours) {
        return transactionService.getRecentFailedTransactions(hours)
            .stream()
            .map(this::toSummary)
            .collect(Collectors.toList());
    }
    
    @GetMapping("/dashboard")
    public Map<String, Object> getDashboard() {
        Map<String, Object> dashboard = new HashMap<>();
        
        List<SecurityEvent> highSeverityEvents = securityEventService.getRecentHighSeverityEvents(24);
        List<TransactionSummary> anomalousTransactions = transactionService.getAnomalousTransactions()
            .stream()
            .map(this::toSummary)
            .collect(Collectors.toList());
        List<TransactionSummary> failedTransactions = transactionService.getRecentFailedTransactions(24)
            .stream()
            .map(this::toSummary)
            .collect(Collectors.toList());
        
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

    private TransactionSummary toSummary(Transaction tx) {
        String username = tx.getUser() != null ? tx.getUser().getUsername() : "guest";
        return new TransactionSummary(
            tx.getId(),
            tx.getTransactionId(),
            tx.getAmount(),
            tx.getStatus().name(),
            tx.isSuspicious(),
            tx.getTransactionDate(),
            username
        );
    }

    public record TransactionSummary(
        Long id,
        String transactionId,
        BigDecimal amount,
        String status,
        boolean suspicious,
        java.time.LocalDateTime transactionDate,
        String username
    ) {}
}
