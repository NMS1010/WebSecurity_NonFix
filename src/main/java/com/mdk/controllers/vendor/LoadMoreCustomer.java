package com.mdk.controllers.vendor;

import static com.mdk.utils.AppConstant.STORE_MODEL;
import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Store;
import com.mdk.models.UserFollowStore;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.IUserFollowStoreService;
import com.mdk.services.impl.UserFollowStoreService;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = "/vendor/loadmore-customer")
public class LoadMoreCustomer extends HttpServlet{

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    IUserFollowStoreService followStoreService = new UserFollowStoreService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setCharacterEncoding("UTF-8");
        int exist = Integer.parseInt(req.getParameter("exist"));
        int indexPage = exist / TOTAL_ITEM_IN_PAGE + 1;
        if (exist % TOTAL_ITEM_IN_PAGE != 0) {
            indexPage++;
        }
        List<UserFollowStore> followStores = new ArrayList<>();
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);
        if (store != null) {
            Pageble pageble = new PageRequest(indexPage, TOTAL_ITEM_IN_PAGE, null);
            followStores = followStoreService.findByStoreId(pageble, store.getId());
        }
        PrintWriter out = resp.getWriter();
        for (UserFollowStore o : followStores) {
//            String urlAvatar = req.getContextPath() + "/image?fname="+o.getUser().getAvatar()+"&type=user";
            String urlAvatarDefault = req.getContextPath() + "/template/images/default-avatar.png";
            out.println("<tr class=\"customer\">\r\n"
                    + "                                                                                                <td>\r\n"
                    + "                                                                                                        <div class=\"d-flex align-items-center mb-1\">\r\n"
                    + "                                                                                                                <c:choose>\r\n"
                    + "                                                                                                                        <c:when test=\"${review.user.avatar != null}\">\r\n"
                    + "                                                                                                                                <c:url value=\"/image?fname=${followStore.user.avatar}&type=user\" var=\"imgAvatar\"></c:url>\r\n"
                    + "                                                                                                                        </c:when>\r\n"
                    + "                                                                                                                        <c:otherwise>\r\n"
                    + "                                                                                                                                <c:url value='/template/images/default-avatar.png' var=\"imgAvatar\" />\r\n"
                    + "                                                                                                                        </c:otherwise>\r\n"
                    + "                                                                                                                </c:choose>\r\n"
                    + "                                                                                                                <img class=\"rounded-circle img-fluid avatar-40\" src=\""+urlAvatarDefault+"\" alt=\"profile\">\r\n"
                    + "                                                                                                                <p class=\"mt-3 ml-1 mr-3\">"+o.getUser().getFirstname()+" "+o.getUser().getLastname()+"</p>\r\n"
                    + "                                                                                                                <div>\r\n"
                    + "                                                                                                                    <p class=\"mt-3 ml-1 mr-3\">Giới tính: "+o.getUser().getSex()+"</p>\r\n"
                    + "                                                                                                                    <p class=\"mt-3 ml-1 mr-3\">Số điện thoại: "+o.getUser().getPhone()+"</p>\r\n"
                    + "                                                                                                                    <p class=\"mt-3 ml-1 mr-3\">Email: "+o.getUser().getEmail()+"</p>\r\n"
                    + "                                                                                                                </div>"
                    + ""
                    + "                                                                                                            </div>\r\n"
                    + "                                                                                                </td>\r\n"
                    + "                                                                                                <td>Đang theo dõi</td>\r\n"
                    + "                                                                                        </tr>");
        }
    }

}
