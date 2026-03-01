package com.security.monitoring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableAsync
@EnableScheduling
// standalone microservice for security event ingestion, correlation, and alerting
public class SecurityMonitoringApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityMonitoringApplication.class, args);
    }
}
