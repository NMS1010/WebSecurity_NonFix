package com.mdk.dao;

import com.mdk.models.ImageStore;

import java.util.List;

public interface IImageStoreDAO {
    void insert (ImageStore image);
    void delete(int storeId);
    List<ImageStore> findByStoreId(int id);

}
