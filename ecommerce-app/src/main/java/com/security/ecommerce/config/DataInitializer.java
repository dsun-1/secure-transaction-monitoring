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
            // Create test users if they don't exist
            if (!userRepository.existsByUsername("testuser")) {
                User user = new User();
                user.setUsername("testuser");
                user.setEmail("test@example.com");
                user.setPassword(passwordEncoder.encode("password123"));
                user.setRole("USER");
                user.setActive(true);
                userRepository.save(user);
            }
            
            if (!userRepository.existsByUsername("admin")) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setEmail("admin@example.com");
                admin.setPassword(passwordEncoder.encode("admin123"));
                admin.setRole("ADMIN");
                admin.setActive(true);
                userRepository.save(admin);
            }
            
            // Create sample products
            if (productRepository.count() == 0) {
                Product product1 = new Product();
                product1.setName("Premium Laptop");
                product1.setDescription("High-performance laptop for developers");
                product1.setPrice(java.math.BigDecimal.valueOf(999.99));
                product1.setStock(50);
                product1.setActive(true);
                productRepository.save(product1);
                
                Product product2 = new Product();
                product2.setName("Wireless Mouse");
                product2.setDescription("Ergonomic wireless mouse");
                product2.setPrice(java.math.BigDecimal.valueOf(29.99));
                product2.setStock(100);
                product2.setActive(true);
                productRepository.save(product2);
                
                Product product3 = new Product();
                product3.setName("Mechanical Keyboard");
                product3.setDescription("RGB mechanical keyboard with Cherry MX switches");
                product3.setPrice(java.math.BigDecimal.valueOf(149.99));
                product3.setStock(75);
                product3.setActive(true);
                productRepository.save(product3);
                
                Product product4 = new Product();
                product4.setName("27-inch Monitor");
                product4.setDescription("4K UHD monitor with HDR support");
                product4.setPrice(java.math.BigDecimal.valueOf(399.99));
                product4.setStock(30);
                product4.setActive(true);
                productRepository.save(product4);
                
                Product product5 = new Product();
                product5.setName("USB-C Hub");
                product5.setDescription("7-in-1 USB-C hub with HDMI and ethernet");
                product5.setPrice(java.math.BigDecimal.valueOf(49.99));
                product5.setStock(150);
                product5.setActive(true);
                productRepository.save(product5);
                
                Product product6 = new Product();
                product6.setName("Webcam");
                product6.setDescription("1080p HD webcam for video calls");
                product6.setPrice(java.math.BigDecimal.valueOf(79.99));
                product6.setStock(60);
                product6.setActive(true);
                productRepository.save(product6);
                
                Product product7 = new Product();
                product7.setName("Headset");
                product7.setDescription("Noise-cancelling wireless headset");
                product7.setPrice(java.math.BigDecimal.valueOf(199.99));
                product7.setStock(40);
                product7.setActive(true);
                productRepository.save(product7);
                
                Product product8 = new Product();
                product8.setName("External SSD");
                product8.setDescription("1TB portable SSD");
                product8.setPrice(java.math.BigDecimal.valueOf(129.99));
                product8.setStock(80);
                product8.setActive(true);
                productRepository.save(product8);
                
                System.out.println("✅ Created 8 test products");
            }
            
            System.out.println("✅ Database initialized with test data");
            System.out.println("📝 Test Users:");
            System.out.println("   Username: testuser | Password: password123");
            System.out.println("   Username: admin    | Password: admin123");
        };
    }
}
