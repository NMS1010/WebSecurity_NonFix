package com.mdk.services.impl;

import com.mdk.dao.ITransactionDAO;
import com.mdk.dao.impl.TransactionDAO;
import com.mdk.models.Transaction;
import com.mdk.paging.Pageble;
import com.mdk.services.ITransactionService;

import java.util.List;

public class TransactionService implements ITransactionService {
    ITransactionDAO transactionDAO = new TransactionDAO();

    @Override
    public List<Transaction> findAll(Pageble pageble, int userId) {
        return transactionDAO.findAll(pageble, userId);
    }

    @Override
    public int count(int storeId, String dateStart, String dateEnd) {
        return transactionDAO.count(storeId, dateStart, dateEnd);
    }

    @Override
    public List<Transaction> findAll(Pageble pageble, int storeId, String dateStart, String dateEnd) {
        return transactionDAO.findAll(pageble, storeId, dateStart, dateEnd);
    }

    @Override
    public void insert(Transaction transaction) {
        transactionDAO.insert(transaction);
    }

    @Override
    public List<Transaction> findAll(Pageble pageble, int storeId, String keyword) {
        return transactionDAO.findAll(pageble, storeId, keyword);
    }

    @Override
    public List<Transaction> findAllForReport() {
        return transactionDAO.findAllForReport();
    }

    @Override
    public int count(int storeId, String keyword) {
        return transactionDAO.count(storeId, keyword);
    }

}
