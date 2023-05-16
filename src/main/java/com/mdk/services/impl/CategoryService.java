package com.mdk.services.impl;

import com.mdk.dao.ICategoryDAO;
import com.mdk.dao.impl.CategoryDAO;
import com.mdk.models.Category;
import com.mdk.paging.Pageble;
import com.mdk.services.ICategoryService;

import java.util.List;

public class CategoryService implements ICategoryService {
    ICategoryDAO categoryDAO = new CategoryDAO();
    @Override
    public Category findById(int id) {
        return categoryDAO.findById(id);
    }

    @Override
    public int count(String state, String keyword) {
        return categoryDAO.count(state, keyword);
    }

    @Override
    public List<Category> findAll(Pageble pageble, String state, String keyword) {
        return categoryDAO.findAll(pageble, state, keyword);
    }

    @Override
    public List<Category> findAll() {
        return categoryDAO.findAll();
    }

    @Override
    public void insert(Category category) {
        categoryDAO.insert(category);
    }

    @Override
    public void edit(Category category) {
        categoryDAO.edit(category);
    }

    @Override
    public void delete(int id) {
        categoryDAO.delete(id);
    }

    @Override
    public void deleteSoft(int id) {
        categoryDAO.deleteSoft(id);
    }

    @Override
    public void restore(int id) {
        categoryDAO.restore(id);
    }

}
