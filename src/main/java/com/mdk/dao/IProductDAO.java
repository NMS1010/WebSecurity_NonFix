package com.mdk.dao;

import java.util.List;

import com.mdk.models.Product;
import com.mdk.paging.Pageble;

public interface IProductDAO {
    void insert(Product product);
    void update(Product product);
    void delete(int id);
    void updateRating(int productId, int rating);
    void ban(int id, Boolean state);
    void updateSold(int id, int sold);
    String findOwnerEmailByProductId(int id);
    Product findOneByName(String name, int storeId);
    Product findOneById(int id);
    List<Product> getTopSeller(int index);
    List<Product> findAll();
    List<Product> findAll(Pageble pageble, int categoryId, int storeId, String searchKey);
    List<Product> findAll(Pageble pageble, String status, int storeId, String searchKey);
    List<Product> findByCategoryId(int categoryId);
//    List<Product> findByStoreId(int storeId);
    int count(int categoryId, int storeId, String searchKey);
    int count(String status, int storeId, String searchKey);
//    List<Product> findAll(Pageble pageble, String status);
    List<Product> findAllByStoreId(int id);
    List<Product> findBySearching(String keyword, int categoryId, int storeId, int rating, double minPrice, double maxPrice);
    List<Product> getTopRating(int index);
    List<Product> findByStoreId(int storeId);
    List<Product> findAllProductProhibited();
    List<Product> findAllProductPermitted();
    List<Product> topSeller(int storeId, int top);
    int countLikeProduct(int productId);
    List<Product> findAll(Pageble pageble);
}
