package com.security.ecommerce.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * SIEM Configuration
 * Enables async processing and scheduled correlation analysis
 */
@Configuration
@EnableAsync
@EnableScheduling
public class SiemConfig {
    // Configuration for SIEM services
    // Async and scheduling annotations enable:
    // - Non-blocking SIEM event transmission
    // - Periodic correlation analysis (every 5 minutes)
}
