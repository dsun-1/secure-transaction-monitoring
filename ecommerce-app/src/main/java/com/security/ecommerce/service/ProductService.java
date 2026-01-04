package com.security.ecommerce.service;

import com.security.ecommerce.model.Product;
import com.security.ecommerce.repository.ProductRepository;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class ProductService {

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    public Product getProductById(@NonNull Long id) {
        return productRepository.findById(id).orElse(null);
    }

    public List<Product> getActiveProducts() {
        return productRepository.findByActiveTrue();
    }

    public Product save(@NonNull Product product) {
        return productRepository.save(product);
    }
}
