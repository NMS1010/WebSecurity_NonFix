package com.mdk.controllers.vendor;

import com.google.gson.Gson;
import com.mdk.models.Store;
import com.mdk.services.IStoreService;
import com.mdk.services.impl.StoreService;
import com.mdk.utils.SessionUtil;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.mdk.utils.AppConstant.STORE_MODEL;

@WebServlet(urlPatterns = {"/vendor/statistic/loadchart"})
public class LoadChartRevenue extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        IStoreService storeService = new StoreService();
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);

        Gson gsonObj = new Gson();
        Map<Object, Object> map = null;
        List<Map<Object, Object>> list = new ArrayList<Map<Object, Object>>();

        String year = req.getParameter("year");
        int storeId = store.getId();

        for(int i = 1; i <= 12; i ++) {
            double revenue = storeService.revenueOfMonth(storeId, String.valueOf(i), year);
            map = new HashMap<Object, Object>();
            map.put("label", "Tháng " + String.valueOf(i));
            map.put("y", revenue);
            list.add(map);
        }
        String dataPoints = gsonObj.toJson(list);
        PrintWriter out = resp.getWriter();
        out.println(dataPoints);
    }
}
