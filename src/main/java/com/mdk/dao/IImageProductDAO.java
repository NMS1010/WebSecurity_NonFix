package com.mdk.dao;

import java.util.List;

import com.mdk.models.ImageProduct;

public interface IImageProductDAO {
    void insert (ImageProduct image);
    void delete(int productId);
    List<ImageProduct> findByProductId(int id);
}
