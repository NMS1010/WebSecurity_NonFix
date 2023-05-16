package com.mdk.controllers.vendor;

import static com.mdk.utils.AppConstant.STORE_MODEL;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.gson.Gson;
import com.mdk.models.Store;
import com.mdk.services.IReviewService;
import com.mdk.services.impl.ReviewService;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = {"/vendor/review/loadchart"})
public class LoadChartRating extends HttpServlet{
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        IReviewService reviewService = new ReviewService();
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);

        Gson gsonObj = new Gson();
        Map<Object, Object> map = null;
        List<Map<Object, Object>> list = new ArrayList<Map<Object, Object>>();
        double countTotal = reviewService.count(store.getId(), "all", null);

        for(int i = 1; i <= 5; i ++) {
            double count = reviewService.count(store.getId(), String.valueOf(i), null);
            double percent = (count / countTotal)*100;
            map = new HashMap<Object, Object>();
            map.put("label", String.valueOf(i) + " Sao");
            map.put("y", (double) Math.round(percent*100)/100);
            list.add(map);
        }
        String dataPoints = gsonObj.toJson(list);
        PrintWriter out = resp.getWriter();
        out.println(dataPoints);
    }

}
