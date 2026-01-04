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

    private String sessionId;

    private String ipAddress;

    private String userAgent;

    private LocalDateTime transactionDate = LocalDateTime.now();

    private String failureReason;

    private Integer attemptCount = 1;

    private boolean suspicious = false;

    private String suspicionReason;

    
    private String couponCode;

    private BigDecimal discountAmount;

    public enum TransactionStatus {
        PENDING,
        AUTHORIZED,
        COMPLETED,
        FAILED,
        DECLINED,
        SUSPICIOUS,
        FRAUDULENT
    }

    
    public boolean isAmountTampered() {
        if (originalAmount != null && amount != null) {
            return originalAmount.compareTo(amount) != 0;
        }
        return false;
    }

    
    public void markSuspicious(String reason) {
        this.suspicious = true;
        this.suspicionReason = reason;
        this.status = TransactionStatus.SUSPICIOUS;
    }
}
