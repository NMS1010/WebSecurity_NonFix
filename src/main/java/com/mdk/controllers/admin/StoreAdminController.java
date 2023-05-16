package com.mdk.controllers.admin;


import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Store;
import com.mdk.models.User;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.IStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.ExportExcel;

@WebServlet(urlPatterns = {"/admin/store/all", "/admin/store/statistic", "/admin/store/all/delete-soft", "/admin/store/all/delete", "/admin/store/all/restore"})
public class StoreAdminController extends HttpServlet{

    private static final long serialVersionUID = 1L;
    IStoreService storeService = new StoreService();
    IUserService userService = new UserService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        if (url.contains("admin/store/all/delete-soft")) {
            String id = req.getParameter("id");
            storeService.deleteSoft(Integer.parseInt(id));
            sendEmail(req, resp, id, "false");
            resp.sendRedirect(req.getContextPath() + "/admin/store/all?state=true");
        }
        else if (url.contains("admin/store/all/delete")) {
            String id = req.getParameter("id");
            storeService.delete(Integer.parseInt(id));

            resp.sendRedirect(req.getContextPath() + "/admin/store/all?state=false");
        }
        else if (url.contains("admin/store/all/restore")) {
            String id = req.getParameter("id");
            storeService.restore(Integer.parseInt(id));
            sendEmail(req, resp, id, "true");
            resp.sendRedirect(req.getContextPath() + "/admin/store/all?state=false");
        }
        else if (url.contains("admin/store/all")) {
            storePage(req, resp);
            List<Store> reportStore = storeService.findAllForReport();
            for (Store item: reportStore)
                item.setAvatar(userService.findById(item.getOwnerID()).getLastname() + " " + userService.findById(item.getOwnerID()).getFirstname());
            final String excelFilePath = "E:\\reportStore.xls";
            ExportExcel.writeExcel(reportStore, excelFilePath, Store.getColumns(), "reportStore");
            req.getRequestDispatcher("/views/admin/store/all.jsp").forward(req, resp);
        }
        else if (url.contains("admin/store/statistic")) {
            LocalDate localDate = LocalDate.now();
            List<Store> storeListTop10 = storeService.top10Store_Orders();
			int total = storeService.totalStores();
            List<Integer> arrEachMonth = new ArrayList<Integer>();
            List<Store> storeList = storeService.findAll();
            List<Integer> arr = new ArrayList<Integer>();
            List<Integer> arrEachMonthInLastYear = new ArrayList<Integer>();
            int open = 0;
            for (Store item: storeList)
                if (item.isOpen() == true)
                    open++;
            int count = 0;
            int totalUserByMonth = 0;
            while (arrEachMonth.size() < 12) {
                count++;
                int totalEachMonth = 0;
                int totalUserByMonthInLastYear = 0;
                for (Store item: storeList)
                    if (Integer.parseInt(item.getCreatedAt().toString().substring(5,7)) == count && Integer.parseInt(item.getCreatedAt().toString().substring(0,4)) == localDate.getYear())
                        totalEachMonth++;
                    else if (Integer.parseInt(item.getCreatedAt().toString().substring(5,7)) == count && Integer.parseInt(item.getCreatedAt().toString().substring(0,4)) == (localDate.getYear()-1))
                        totalUserByMonthInLastYear++;
                totalUserByMonth += totalEachMonth;
                arr.add(totalUserByMonth);
                arrEachMonth.add(totalEachMonth);
                arrEachMonthInLastYear.add(totalUserByMonthInLastYear);
            }
            req.setAttribute("arrEachMonth", arrEachMonth);
            req.setAttribute("arrEachMonthInLastYear", arrEachMonthInLastYear);
            req.setAttribute("arrByMonth", arr);
			req.setAttribute("storeListTop10", storeListTop10);
			req.setAttribute("open", open);
            req.setAttribute("total", total);
            req.getRequestDispatcher("/views/admin/store/statistic.jsp").forward(req, resp);
        }

    }

    protected void storePage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        String indexPage = req.getParameter("index");
        String searchKey = req.getParameter("search");
        if(indexPage == null) {
            indexPage = "1";
        }
        String state = req.getParameter("state") == null ? "true" : req.getParameter("state");
        int countP = storeService.count(searchKey, state);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Store> storeList = storeService.findAll(pageble, searchKey, state);
        List<String> listNameOwner = new ArrayList<String>();
        for (Store item: storeList) {
            User user = userService.findById(item.getOwnerID());
            listNameOwner.add(user.getLastname() +" "+ user.getFirstname());
        }
        req.setAttribute("state", state);
        req.setAttribute("countP", countP);
        req.setAttribute("totalItemInPage", totalItemInPage);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("storeList", storeList);
        req.setAttribute("listNameOwner", listNameOwner);
    }

    protected void sendEmail(HttpServletRequest req, HttpServletResponse resp, String storeId, String state) throws ServletException, IOException {
        List<String> data = storeService.findOwnerEmailByStoreId(Integer.parseInt(storeId));
        Store store = storeService.findById(Integer.parseInt(storeId));
        resp.setContentType("text/html");

        String subject = "", img = "", mainTitle = "", subTitle = "";
        if (state.equals("true")) {
            subject = "Cửa hàng của bạn được mở bán trở lại";
            img = "https://img.freepik.com/free-vector/shop-with-we-are-open-sign_23-2148557016.jpg";
            mainTitle = "MỞ BÁN";
            subTitle = "Sau khi hệ thống xem xét lại tiêu chuẩn cộng động, hệ thống xin chúc mừng cửa hàng của bạn đã được bán trở lại.";
        } else {
            subject = "Cửa hàng cửa bạn bị cấm bán";
            img = "https://st.depositphotos.com/1064545/2274/i/600/depositphotos_22745337-stock-photo-3d-white-forbidden-sign.jpg";
            mainTitle = "CẤM BÁN";
            subTitle = "Cửa hàng của bạn bị cấm bán do vi phạm tiêu chuẩn cộng đồng của hệ thống.";
        }


        final String username = "0509dangle@gmail.com";
        final String password = "pmvcktmweazmgsqt";
        Properties props = new Properties();
        props.put("mail.smtp.auth", true);
        props.put("mail.smtp.starttls.enable", true);
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(data.get(0)));
            message.setSubject(subject, "utf-8");
            String htmlContent = " <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\">\n" +
                    "        <tr>\n" +
                    "            <td bgcolor=\"#FFA73B\" align=\"center\">\n" +
                    "                <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">\n" +
                    "                    <tr>\n" +
                    "                        <td align=\"center\" valign=\"top\" style=\"padding: 40px 10px 40px 10px;\"> </td>\n" +
                    "                    </tr>\n" +
                    "                </table>\n" +
                    "            </td>\n" +
                    "        </tr>\n" +
                    "        <tr>\n" +
                    "            <td bgcolor=\"#FFA73B\" align=\"center\" style=\"padding: 0px 10px 0px 10px;\">\n" +
                    "                <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"center\" valign=\"top\"\n" +
                    "                            style=\"padding: 40px 20px 20px 20px; border-radius: 4px 4px 0px 0px; color: #111111; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 48px; font-weight: 400; letter-spacing: 4px; line-height: 48px;\">\n" +
                    "                            <h1 style=\"font-size: 48px; font-weight: 400; margin: 2;\">"+mainTitle+"</h1> <img\n" +
                    "                                src=\""+img+"\"\n" +
                    "                                width=\"200\" height=\"200\" style=\"display: block; border: 0px;\" />\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                </table>\n" +
                    "            </td>\n" +
                    "        </tr>\n" +
                    "        <tr>\n" +
                    "            <td bgcolor=\"#f4f4f4\" align=\"center\" style=\"padding: 0px 10px 0px 10px;\">\n" +
                    "                <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">"+subTitle+"</p>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">Thông tin cửa hàng:</p>\n" +
                    "                            <ul>\n" +
                    "                                <li>Tên cửa hàng: "+store.getName()+".</li>\n" +
                    "                                <li>Tên chủ cửa hàng: "+data.get(2)+" "+data.get(1)+"</li>\n" +
                    "                            </ul>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">Nếu có bất kì phản hồi nào xin vui\n" +
                    "                                lòng liên hệ vào địa chỉ email sau: <span\n" +
                    "                                    style=\"font-weight: 700; font-style: italic;\">0509dangle@gmail.com</span> .</p>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 40px 30px; border-radius: 0px 0px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">Chào bạn,<br>MDK</p>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                </table>\n" +
                    "            </td>\n" +
                    "        </tr>\n" +
                    "    </table>";
            message.setContent(htmlContent, "text/html;charset=utf-8");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
