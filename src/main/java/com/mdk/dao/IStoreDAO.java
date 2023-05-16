
package com.mdk.dao;

import java.util.List;

import com.mdk.models.Store;
import com.mdk.paging.Pageble;

public interface IStoreDAO {
    void insert(Store store);
    void update(Store store);
    int count(int userId);
    void updateRating(int storeId, int rating);
    int count(String keyword, String state);
    Store findByUserId(int userId);
    int totalCustomer(int storeId);
    int totalProduct(int storeId);
    int totalOrders(int storeId);
    int totalSale(int storeId);
    double revenueOfMonth(int storeId, String month, String year);
    double transactionOfMonth(int storeId, boolean isUp, String month, String year);
    Store findById(int id);
    int totalStores();
    List<Store> top10Store_Orders();
    List<Store> findAll();
    List<Store> findAll(Pageble pageble, String keyword, String state);
    List<Store> findAllByName(String keyword);
    List<String> findOwnerEmailByStoreId(int id);
    void updateWallet(int id, double eWallet);
    void deleteSoft(int id);
    void delete(int id);
    void restore(int id);
    List<Store> findAllForReport();
}
