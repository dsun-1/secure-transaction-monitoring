package com.security.ecommerce.repository;

import com.security.ecommerce.model.Transaction;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    List<Transaction> findByUser_Username(String username);

    List<Transaction> findByStatus(Transaction.TransactionStatus status);

    // pessimistic lock for transaction reads during concurrent checkout flows
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT t FROM Transaction t WHERE t.id = :id")
    Optional<Transaction> findByIdWithLock(@Param("id") Long id);

    @Query("SELECT t FROM Transaction t WHERE t.amount < 0 OR t.amount > 10000")
    List<Transaction> findAnomalousTransactions();

    @Query("SELECT t FROM Transaction t WHERE t.transactionDate > ?1 AND t.status = 'FAILED'")
    List<Transaction> findRecentFailedTransactions(LocalDateTime since);
}
