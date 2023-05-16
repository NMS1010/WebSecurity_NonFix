package com.mdk.controllers.common;

import static com.mdk.utils.AppConstant.ADMIN;
import static com.mdk.utils.AppConstant.CART;
import static com.mdk.utils.AppConstant.CART_HEADER;
import static com.mdk.utils.AppConstant.CART_USER;
import static com.mdk.utils.AppConstant.COUNT_CART_HEADER;
import static com.mdk.utils.AppConstant.STORE_MODEL;
import static com.mdk.utils.AppConstant.USER;
import static com.mdk.utils.AppConstant.USER_MODEL;
import static com.mdk.utils.AppConstant.USER_LOGIN;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Store;
import com.mdk.models.User;
import com.mdk.services.IStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.MessageUtil;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = {"/login", "/logout"})
public class LoginController extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IUserService userService = new UserService();
    IStoreService storeService = new StoreService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        String action = req.getParameter("action") == null ? "" : req.getParameter("action");
        User user = (User) SessionUtil.getInstance().getValue(req, USER_LOGIN);
        if (url.contains("login")) {
            if (user != null) {
                if (action.equals("loginnow")) {
                    ReqLogin(req, resp, user, false);
                } else {
                    ReqLogin(req, resp, user, true);
                }
            }
            else {
                MessageUtil.showMessage(req, resp);
                req.getRequestDispatcher("/views/login.jsp").forward(req, resp);
            }
        } else if (url.contains("logout")) {
            removeSession(req);
            resp.sendRedirect(req.getContextPath() + "/home");
        }
        else {
            req.getRequestDispatcher("/views/home.jsp").forward(req, resp);;
        }

    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        if (url.contains("login")) {
            String username = req.getParameter("username");
            String password = req.getParameter("password");
            User user = new User();
            user.setEmail(username);
            user.setPassword(password);
            ReqLogin(req, resp, user, false);
        }
    }
    
    protected void removeSession(HttpServletRequest req) throws ServletException, IOException {
        SessionUtil.getInstance().removeValue(req, USER_MODEL);
        SessionUtil.getInstance().removeValue(req, CART);
        SessionUtil.getInstance().removeValue(req, CART_HEADER);
        SessionUtil.getInstance().removeValue(req, COUNT_CART_HEADER);
        SessionUtil.getInstance().removeValue(req, CART_USER);
        SessionUtil.getInstance().removeValue(req, STORE_MODEL);
    }
    
    protected void ReqLogin(HttpServletRequest req, HttpServletResponse resp, User userLogin, boolean isLoginGoogle) throws ServletException,
            IOException {
        User user = userService.findOneByUsernameAndPassword(userLogin.getEmail(), userLogin.getPassword());
     
        if (user != null) {
            SessionUtil.getInstance().removeValue(req, USER_LOGIN);
            SessionUtil.getInstance().putValue(req, USER_MODEL, user);
            Store store = storeService.findByUserId(user.getId());
            SessionUtil.getInstance().putValue(req, STORE_MODEL, store);
            if (user.getRole().equals(ADMIN)) {
                resp.sendRedirect(req.getContextPath() + "/admin/user/all");
            } else if (user.getRole().equals(USER)) {
                resp.sendRedirect(req.getContextPath() + "/web");
            } else {
                resp.sendRedirect(req.getContextPath() + "/login?message=login_error");
            }
        } else if (isLoginGoogle){
            resp.sendRedirect(req.getContextPath() + "/signup?action=create&state=loginGoogle");
        } else {
            resp.sendRedirect(req.getContextPath() + "/login?message=login_error");
        }
    }
    
}
