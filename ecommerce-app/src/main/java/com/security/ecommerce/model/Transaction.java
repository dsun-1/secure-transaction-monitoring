package com.security.ecommerce.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;


@Entity
@Table(name = "transactions")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private String transactionId;

    private BigDecimal amount;

    private BigDecimal originalAmount; 

    private String paymentMethod;

    @Enumerated(EnumType.STRING)
    private TransactionStatus status;

    private boolean suspicious = false;

    private LocalDateTime transactionDate = LocalDateTime.now();

    private String failureReason;

    public enum TransactionStatus {
        COMPLETED,
        FAILED
    }
}
