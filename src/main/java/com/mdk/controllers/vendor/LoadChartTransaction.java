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

@WebServlet(urlPatterns = "/vendor/transaction/loadchart")
public class LoadChartTransaction extends HttpServlet {
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
        Map<Object, Object> mapWithDraw = null;
        Map<Object, Object> mapRecharge = null;
        List<Map<Object, Object>> listWithDraw = new ArrayList<Map<Object, Object>>();
        List<Map<Object, Object>> listRecharge = new ArrayList<Map<Object, Object>>();

        String year = req.getParameter("year");
        int storeId = store.getId();

        for(int i = 1; i <= 12; i ++) {
            double withDraw = storeService.transactionOfMonth(storeId, true, String.valueOf(i), year);
            double recharge = storeService.transactionOfMonth(storeId, false, String.valueOf(i), year);
            mapWithDraw = new HashMap<Object, Object>();
            mapWithDraw.put("label", "Tháng " + String.valueOf(i));
            mapWithDraw.put("y", withDraw);

            mapRecharge = new HashMap<Object, Object>();
            mapRecharge.put("label", "Tháng " + String.valueOf(i));
            mapRecharge.put("y", recharge);

            listWithDraw.add(mapWithDraw);
            listRecharge.add(mapRecharge);
        }
        List<String> data = new ArrayList<>();
        String dataPoints1 = gsonObj.toJson(listWithDraw);
        String dataPoints2 = gsonObj.toJson(listRecharge);
        data.add(dataPoints1);
        data.add(dataPoints2);
        PrintWriter out = resp.getWriter();
        out.println(data);
    }

}
