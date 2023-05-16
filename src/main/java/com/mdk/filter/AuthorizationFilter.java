package com.mdk.filter;

import static com.mdk.utils.AppConstant.ADMIN;
import static com.mdk.utils.AppConstant.USER;
import static com.mdk.utils.AppConstant.USER_MODEL;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.User;
import com.mdk.utils.SessionUtil;

public class AuthorizationFilter implements Filter {
    @SuppressWarnings("unused")
    private ServletContext context;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.context = filterConfig.getServletContext();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        String url = req.getRequestURL().toString();
        if (url.contains("admin")) {
            checkAuthor(request, response, chain, ADMIN);
        } else if (url.contains("web") || url.contains("vendor")){
            checkAuthor(request, response, chain, USER);
        } else {
            chain.doFilter(request, response);
        }
    }

    protected void checkAuthor(ServletRequest request, ServletResponse response, FilterChain chain, String role) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        User model = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
        if (model != null) {
            if (model.getRole().equals(role)) {
                chain.doFilter(request,response);
            } else {
                // no permission
                resp.sendRedirect(req.getContextPath() + "/login?message=login_no_permission");
            }
        } else {
            // request login
            resp.sendRedirect(req.getContextPath() + "/login?message=login_no");
        }
    }

    @Override
    public void destroy() {
    }
}
