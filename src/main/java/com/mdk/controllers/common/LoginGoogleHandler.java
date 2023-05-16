package com.mdk.controllers.common;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.fluent.Form;
import org.apache.http.client.fluent.Request;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mdk.models.User;
import com.mdk.models.UserGoogle;
import com.mdk.utils.AppConstant;
import com.mdk.utils.SessionUtil;
import static com.mdk.utils.AppConstant.USER_LOGIN;

@WebServlet(urlPatterns = "/LoginGoogleHandler")
public class LoginGoogleHandler extends HttpServlet{

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        SessionUtil.getInstance().putValue(req, USER_LOGIN, toUser(req, resp));
        resp.sendRedirect(req.getContextPath() + "/login");
    }
    

    protected String getToken(String code) throws ClientProtocolException, IOException {
        // call api to get token
        String response = Request.Post(AppConstant.GOOGLE_LINK_GET_TOKEN)
                .bodyForm(Form.form().add("client_id", AppConstant.GOOGLE_CLIENT_ID)
                        .add("client_secret", AppConstant.GOOGLE_CLIENT_SECRET)
                        .add("redirect_uri", AppConstant.GOOGLE_REDIRECT_URI).add("code", code)
                        .add("grant_type", AppConstant.GOOGLE_GRANT_TYPE).build())
                .execute().returnContent().asString();

        JsonObject jobj = new Gson().fromJson(response, JsonObject.class);
        String accessToken = jobj.get("access_token").toString().replaceAll("\"", "");
        return accessToken;
    }
    

    protected UserGoogle getUserInfo(final String accessToken) throws ClientProtocolException, IOException {
        String link = AppConstant.GOOGLE_LINK_GET_USER_INFO + accessToken;
        String response = Request.Get(link).execute().returnContent().asString();
        System.out.println(response);
        UserGoogle googlePojo = new Gson().fromJson(response, UserGoogle.class);
        return googlePojo;
    }
    protected User toUser(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        User user = new User();
        String code = req.getParameter("code");
        String accessToken = getToken(code);
        UserGoogle userGoogle = getUserInfo(accessToken);
        user.setEmail(userGoogle.getEmail());
        user.setFirstname(userGoogle.getGiven_name());
        user.setLastname(userGoogle.getFamily_name());
        user.setPassword(userGoogle.getId());
        return user;
    }

}
