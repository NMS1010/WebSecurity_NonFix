package com.mdk.services.impl;

import com.mdk.dao.IImageStoreDAO;
import com.mdk.dao.impl.ImageStoreDAO;
import com.mdk.models.ImageStore;
import com.mdk.services.IImageStoreService;

import java.util.List;

public class ImageStoreService implements IImageStoreService {
    IImageStoreDAO imageStoreDAO = new ImageStoreDAO();
    @Override
    public void insert(ImageStore image) {
        imageStoreDAO.insert(image);
    }

    @Override
    public List<ImageStore> findByStoreId(int id) {
        return imageStoreDAO.findByStoreId(id);
    }

    @Override
    public void delete(int storeId) {
        imageStoreDAO.delete(storeId);
    }
}
