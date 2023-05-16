package com.mdk.services.impl;

import com.mdk.dao.IUserDAO;
import com.mdk.dao.impl.UserDAO;
import com.mdk.models.User;
import com.mdk.paging.Pageble;
import com.mdk.services.IUserService;

import java.util.List;

public class UserService implements IUserService {
    IUserDAO userDao = new UserDAO();

    @Override
    public List<User> findAll() {
        return userDao.findAll();
    }

    @Override
    public User findById(int id) {
        return userDao.findById(id);
    }

    @Override
    public List<User> top10Users_Orders() {
        return userDao.top10Users_Orders();
    }

    @Override
    public int count(String keyword) {
        return userDao.count(keyword);
    }

    @Override
    public List<User> findAll(Pageble pageble, String keyword) {
        return userDao.findAll(pageble, keyword);
    }

    @Override
    public User findOneByUsernameAndPassword(String username, String password) {
        return userDao.findOneByUsernameAndPassword(username, password);
    }

	@Override
	public void insert(User user) {
		userDao.insert(user);
	}

	@Override
	public void update(User user) {
		userDao.update(user);
	}

	@Override
	public void delete(int id) {
		userDao.delete(id);
	}

	@Override
	public List<User> findBySearching(String keyword) {
		return userDao.findBySearching(keyword);
	}

    @Override
    public List<User> findAllForReport() {
        return userDao.findAllForReport();
    }

    @Override
	public void updateWallet(int id, double eWallet) {
		userDao.updateWallet(id, eWallet);
	}

    @Override
    public int checkEmailExist(String email) {
        return userDao.checkEmailExist(email);
    }

	@Override
	public int checkPhoneExist(String phone) {
		return userDao.checkPhoneExist(phone);
	}

	@Override
	public int checkId_card(String id_card) {
		// TODO Auto-generated method stub
		return userDao.checkId_card(id_card);
	}

	@Override
	public void updatePass(int id, String pass) {
		userDao.updatePass(id, pass);
	}

}
