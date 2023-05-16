package com.mdk.services.impl;

import com.mdk.dao.IImageProductDAO;
import com.mdk.dao.impl.ImageProductDAO;
import com.mdk.models.ImageProduct;
import com.mdk.services.IImageProductService;

import java.util.List;

public class ImageProductService implements IImageProductService {
    IImageProductDAO imageProductDAO = new ImageProductDAO();
    @Override
    public void insert(ImageProduct image) {
        imageProductDAO.insert(image);
    }
    @Override
    public void delete(int productId) {
        imageProductDAO.delete(productId);
    }
    @Override
    public List<ImageProduct> findByProductId(int id) {
        return imageProductDAO.findByProductId(id);
    }
}
