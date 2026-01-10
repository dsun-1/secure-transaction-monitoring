package com.security.ecommerce.config;

import com.security.ecommerce.model.Product;
import com.security.ecommerce.model.User;
import com.security.ecommerce.repository.ProductRepository;
import com.security.ecommerce.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {
    
    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository, 
                                    ProductRepository productRepository,
                                    PasswordEncoder passwordEncoder) {
        return args -> {
            
            User testUser = userRepository.findByUsername("testuser").orElse(null);
            if (testUser == null) {
                testUser = new User();
                testUser.setUsername("testuser");
                testUser.setEmail("test@example.com");
                testUser.setPassword(passwordEncoder.encode("password123"));
                testUser.setRole("USER");
                testUser.setActive(true);
            } else {
                testUser.resetFailedAttempts();
                testUser.setAccountNonLocked(true);
                testUser.setAccountLockedUntil(null);
                testUser.setPassword(passwordEncoder.encode("password123"));
                testUser.setActive(true);
            }
            userRepository.save(testUser);

            User admin = userRepository.findByUsername("admin").orElse(null);
            if (admin == null) {
                admin = new User();
                admin.setUsername("admin");
                admin.setEmail("admin@example.com");
                admin.setPassword(passwordEncoder.encode("admin123"));
                admin.setRole("ADMIN");
                admin.setActive(true);
            } else {
                admin.resetFailedAttempts();
                admin.setAccountNonLocked(true);
                admin.setAccountLockedUntil(null);
                admin.setPassword(passwordEncoder.encode("admin123"));
                admin.setActive(true);
            }
            userRepository.save(admin);

            User paymentUser = userRepository.findByUsername("paymentuser").orElse(null);
            if (paymentUser == null) {
                paymentUser = new User();
                paymentUser.setUsername("paymentuser");
                paymentUser.setEmail("paymentuser@example.com");
                paymentUser.setPassword(passwordEncoder.encode("Paym3nt@123"));
                paymentUser.setRole("USER");
                paymentUser.setActive(true);
            } else {
                paymentUser.resetFailedAttempts();
                paymentUser.setAccountNonLocked(true);
                paymentUser.setAccountLockedUntil(null);
                paymentUser.setPassword(passwordEncoder.encode("Paym3nt@123"));
                paymentUser.setActive(true);
            }
            userRepository.save(paymentUser);
            
            
            if (productRepository.count() == 0) {
                Product product1 = new Product();
                product1.setName("Premium Laptop");
                product1.setDescription("High-performance laptop for developers");
                product1.setPrice(java.math.BigDecimal.valueOf(999.99));
                product1.setStock(50);
                productRepository.save(product1);
                
                Product product2 = new Product();
                product2.setName("Wireless Mouse");
                product2.setDescription("Ergonomic wireless mouse");
                product2.setPrice(java.math.BigDecimal.valueOf(29.99));
                product2.setStock(100);
                productRepository.save(product2);
                
                Product product3 = new Product();
                product3.setName("Mechanical Keyboard");
                product3.setDescription("RGB mechanical keyboard with Cherry MX switches");
                product3.setPrice(java.math.BigDecimal.valueOf(149.99));
                product3.setStock(75);
                productRepository.save(product3);
                
                Product product4 = new Product();
                product4.setName("27-inch Monitor");
                product4.setDescription("4K UHD monitor with HDR support");
                product4.setPrice(java.math.BigDecimal.valueOf(399.99));
                product4.setStock(30);
                productRepository.save(product4);
                
                Product product5 = new Product();
                product5.setName("USB-C Hub");
                product5.setDescription("7-in-1 USB-C hub with HDMI and ethernet");
                product5.setPrice(java.math.BigDecimal.valueOf(49.99));
                product5.setStock(150);
                productRepository.save(product5);
                
                Product product6 = new Product();
                product6.setName("Webcam");
                product6.setDescription("1080p HD webcam for video calls");
                product6.setPrice(java.math.BigDecimal.valueOf(79.99));
                product6.setStock(60);
                productRepository.save(product6);
                
                Product product7 = new Product();
                product7.setName("Headset");
                product7.setDescription("Noise-cancelling wireless headset");
                product7.setPrice(java.math.BigDecimal.valueOf(199.99));
                product7.setStock(40);
                productRepository.save(product7);
                
                Product product8 = new Product();
                product8.setName("External SSD");
                product8.setDescription("1TB portable SSD");
                product8.setPrice(java.math.BigDecimal.valueOf(129.99));
                product8.setStock(80);
                productRepository.save(product8);
                
                System.out.println("INFO: Created 8 test products");
            }
            
            System.out.println("INFO: Database initialized with demo test data");
            System.out.println("INFO: Demo users (demo profile only):");
            System.out.println("INFO: Username: testuser | Password: password123");
            System.out.println("INFO: Username: admin    | Password: admin123");
        };
    }
}

