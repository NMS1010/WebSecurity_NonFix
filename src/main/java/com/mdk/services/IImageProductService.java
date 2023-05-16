package com.mdk.services;

import com.mdk.models.ImageProduct;

import java.util.List;

public interface IImageProductService {
    void insert (ImageProduct image);
    void delete(int productId);
    List<ImageProduct> findByProductId(int id);
}
