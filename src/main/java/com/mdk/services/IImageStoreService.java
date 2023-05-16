package com.mdk.services;

import com.mdk.models.ImageStore;

import java.util.List;

public interface IImageStoreService {
    void insert (ImageStore image);
    List<ImageStore> findByStoreId(int id);
    void delete (int storeId);

}
