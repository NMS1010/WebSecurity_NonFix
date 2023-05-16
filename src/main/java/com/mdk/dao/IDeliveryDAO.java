package com.mdk.dao;

import java.util.List;

import com.mdk.models.Delivery;
import com.mdk.paging.Pageble;

public interface IDeliveryDAO {
    List<Delivery> findAllActive();
    void insert(Delivery delivery);
    void edit(Delivery delivery);
    void deleteSoft(int id);
    void delete(int id);
    void restore(int id);
    void updateStatus(Delivery delivery);
    Delivery findById(int id);
    int count(String state, String keyword);
    List<Delivery> findAll(Pageble pageble, String state, String keyword);
}
