package com.mdk.controllers.vendor;

import com.mdk.models.Store;
import com.mdk.utils.SessionUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.mdk.utils.AppConstant.STORE_MODEL;

public class CheckStoreExist extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public static boolean checkStoreExist(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);
        if (store != null) {
            return true;
        }
        return false;
    }
}
