package com.security.monitoring.controller;

import com.security.monitoring.model.ThreatIntelligence;
import com.security.monitoring.repository.MonitoringEventRepository;
import com.security.monitoring.repository.ThreatIntelligenceRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/analytics")
// dashboard and analytics endpoints for the monitoring ui
public class AnalyticsController {

    private final MonitoringEventRepository eventRepository;
    private final ThreatIntelligenceRepository threatRepository;

    public AnalyticsController(MonitoringEventRepository eventRepository,
                               ThreatIntelligenceRepository threatRepository) {
        this.eventRepository = eventRepository;
        this.threatRepository = threatRepository;
    }

    // event summary aggregated by type and severity
    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> getEventSummary(
        @RequestParam(defaultValue = "24") int hours
    ) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);

        List<Object[]> eventSummary = eventRepository.getEventSummary(since);
        List<Object[]> layerSummary = eventRepository.getLayerSummary(since);

        List<Map<String, Object>> events = eventSummary.stream().map(row -> {
            Map<String, Object> m = new HashMap<>();
            m.put("eventType", row[0]);
            m.put("severity", row[1]);
            m.put("count", row[2]);
            return m;
        }).collect(Collectors.toList());

        List<Map<String, Object>> layers = layerSummary.stream().map(row -> {
            Map<String, Object> m = new HashMap<>();
            m.put("layer", row[0]);
            m.put("count", row[1]);
            return m;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(Map.of(
            "period_hours", hours,
            "events_by_type", events,
            "events_by_layer", layers,
            "generated_at", LocalDateTime.now().toString()
        ));
    }

    // active threats from the correlation engine
    @GetMapping("/threats")
    public ResponseEntity<List<ThreatIntelligence>> getActiveThreats(
        @RequestParam(defaultValue = "24") int hours
    ) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        List<ThreatIntelligence> threats = threatRepository.findBySeverityAndCreatedAtAfter("HIGH", since);
        threats.addAll(threatRepository.findBySeverityAndCreatedAtAfter("CRITICAL", since));
        return ResponseEntity.ok(threats);
    }

    // threat lookup by source IP for incident response
    @GetMapping("/threats/ip/{ip}")
    public ResponseEntity<List<ThreatIntelligence>> getThreatsByIp(@PathVariable String ip) {
        return ResponseEntity.ok(threatRepository.findBySourceIp(ip));
    }

    // health endpoint for inter-service readiness checks
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        long totalEvents = eventRepository.count();
        long totalThreats = threatRepository.count();
        long pendingAlerts = threatRepository.findByEscalatedFalse().size();

        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "total_events", totalEvents,
            "total_threats", totalThreats,
            "pending_alerts", pendingAlerts,
            "timestamp", LocalDateTime.now().toString()
        ));
    }
}
