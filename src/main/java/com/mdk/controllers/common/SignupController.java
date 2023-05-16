package com.mdk.controllers.common;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.User;
import com.mdk.services.IUserService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.MessageUtil;
import com.mdk.utils.SessionUtil;
import static com.mdk.utils.AppConstant.USER_LOGIN;

@WebServlet(urlPatterns = {"/signup"})
public class SignupController extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IUserService userService = new UserService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String action = req.getParameter("action");
        MessageUtil.showMessage(req, resp);
        if (action == null) {
            req.getRequestDispatcher("/views/signup.jsp").forward(req, resp);
        } else if (action.equals("verify")) {
            req.getRequestDispatcher("/views/verifyemail.jsp").forward(req, resp);
        }
        else {
            User user = (User) SessionUtil.getInstance().getValue(req, USER_LOGIN);
            userService.insert(user);
            resp.sendRedirect(req.getContextPath() + "/login");
        } 
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String action = req.getParameter("action");
        if (action.equals("create")) {
            String repassword = req.getParameter("re-password");
            String message = checkInfor(req, repassword);
            if (message.equals("")) {
                sendEmail(req, resp);
            } else {
                resp.sendRedirect(req.getContextPath() + "/signup?message=" + message);
            }
        } else if (action.equals("verify")) {
            String code = req.getParameter("code");
            User user = (User) SessionUtil.getInstance().getValue(req, USER_LOGIN);
            if (code.equals(user.getCode())) {
                userService.insert(user);
                resp.sendRedirect(req.getContextPath() + "/login?action=loginnow");
            } else {
                resp.sendRedirect(req.getContextPath() + "/signup?action=verify&message=verify_failed");
            }
        }
    }
   
    
    protected void sendEmail(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        User user = getUser(req);
        SendEmail sm = new SendEmail();
        String code = sm.getRandom();
        boolean isSuccess = sm.sendEmail(user.getEmail(), code);
        if (isSuccess) {
            user.setCode(code);
            SessionUtil.getInstance().putValue(req, USER_LOGIN, user);
            resp.sendRedirect(req.getContextPath() + "/signup?action=verify");
        } else {
            resp.sendRedirect(req.getContextPath() + "/signup?message=signup_error");
        }
        
    }
    
    protected String checkInfor(HttpServletRequest req, String repassword) throws ServletException, IOException {
        String state = req.getParameter("state");
        User user = getUser(req);
        if (state == null) {
            return !checkEmailEixst(user.getEmail()) ? "email_already_exist" : 
                !checkRePassword(user.getPassword(), repassword) ? "password_incorrect" : "";
        }
        return !checkEmailEixst(user.getEmail()) ? "email_already_exist" : "";
    }
    
    protected boolean checkEmailEixst(String email){
        if (userService.checkEmailExist(email) > 0) {
            return false;
        }
        return true;
    }
    
    protected boolean checkRePassword(String password, String repassword){
        if (!password.equals(repassword)) {
            return false;
        }
        return true;
    }
    protected User getUser(HttpServletRequest req) throws ServletException, IOException {
        String state = req.getParameter("state");
        User user = new User();
        if (state == null) {
            user.setFirstname(req.getParameter("firstname"));
            user.setLastname(req.getParameter("lastname"));
            user.setEmail(req.getParameter("email"));
            user.setPassword(req.getParameter("password")); 
            
        } else {
            user = (User) SessionUtil.getInstance().getValue(req, USER_LOGIN);
        }
        return user;
    }
}
