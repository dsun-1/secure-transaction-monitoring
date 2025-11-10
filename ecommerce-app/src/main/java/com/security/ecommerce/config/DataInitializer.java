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
                product1.setDescription("High-performance laptop");
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
                product3.setDescription("RGB mechanical keyboard");
                product3.setPrice(java.math.BigDecimal.valueOf(149.99));
                product3.setStock(75);
                product3.setActive(true);
                productRepository.save(product3);
            }
            
            System.out.println("✅ Database initialized with test data");
        };
    }
}
