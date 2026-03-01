package com.security.ecommerce.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
// rest template bean for inter-service communication with the monitoring
// microservice
public class EventForwardingConfig {

    @Value("${monitoring.service.url:http://localhost:8081}")
    private String monitoringServiceUrl;

    @Bean
    public RestTemplate monitoringRestTemplate() {
        return new RestTemplate();
    }

    @Bean
    public String monitoringServiceUrl() {
        return monitoringServiceUrl;
    }
}
