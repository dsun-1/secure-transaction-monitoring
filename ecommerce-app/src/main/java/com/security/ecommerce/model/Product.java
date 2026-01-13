package com.security.ecommerce.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;


@Entity
@Table(name = "products")
@Data
@NoArgsConstructor
@AllArgsConstructor
// product catalog entry with stock tracking
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Product name is required")
    private String name;

    private String description;

    @NotNull(message = "Price is required")
    @Min(value = 0, message = "Price must be positive")
    private BigDecimal price;

    @Min(value = 0, message = "Stock must be non-negative")
    private Integer stock = 0;

    private String category;

    private String imageUrl;

    private boolean active = true;

    public boolean isInStock() {
        return stock != null && stock > 0;
    }

    public void decrementStock(int quantity) {
        // guard against negative stock on fulfillment
        if (stock >= quantity) {
            stock -= quantity;
        } else {
            throw new IllegalStateException("Insufficient stock");
        }
    }
}
