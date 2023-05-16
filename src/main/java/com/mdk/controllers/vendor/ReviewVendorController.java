package com.mdk.controllers.vendor;

import static com.mdk.controllers.vendor.CheckStoreExist.checkStoreExist;
import static com.mdk.utils.AppConstant.STORE_MODEL;
import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;
import static com.mdk.utils.AppConstant.UPLOAD_PRODUCT_DIRECTORY;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Review;
import com.mdk.models.Store;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.ICategoryService;
import com.mdk.services.IImageProductService;
import com.mdk.services.IProductService;
import com.mdk.services.IReviewService;
import com.mdk.services.impl.CategoryService;
import com.mdk.services.impl.ImageProductService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.ReviewService;
import com.mdk.utils.MessageUtil;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = {"/vendor/review", "/vendor/review/notification"})
public class ReviewVendorController extends HttpServlet{

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    ICategoryService categoryService = new CategoryService();
    IProductService productService = new ProductService();
    IImageProductService imageProductService = new ImageProductService();
    IReviewService reviewService = new ReviewService();
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        if (url.contains("notification")) {
            MessageUtil.showMessage(req, resp);
            req.getRequestDispatcher("/views/vendor/review.jsp").forward(req, resp);
        } else if (url.contains("review")) {
            if (checkStoreExist(req, resp)) {
                reviewPage(req, resp);
                req.getRequestDispatcher("/views/vendor/review.jsp").forward(req, resp);
            } else {
                resp.sendRedirect(req.getContextPath() + "/vendor/review/notification?message=nostore_error");
            }
        }
    }
    
    
    protected void reviewPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);
        
        
        String indexPage = req.getParameter("index");
        String searchKey = req.getParameter("search");
        String starReq = req.getParameter("star") == null ? "all" : req.getParameter("star");
        if(indexPage == null) {
            indexPage = "1";
        }
        int countP = reviewService.count(store.getId(), starReq, searchKey);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Review> reviews = new ArrayList<>();
        reviews = reviewService.findByStore(pageble, store.getId(), starReq, searchKey);
        req.setAttribute("count", countP);
        req.setAttribute("total", totalItemInPage);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("DIR", UPLOAD_PRODUCT_DIRECTORY);
        req.setAttribute("reviews", reviews);
        req.setAttribute("search", searchKey);
        req.setAttribute("starResp", starReq);
    }

}
