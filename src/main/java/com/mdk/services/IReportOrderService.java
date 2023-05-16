package com.mdk.services;

import com.mdk.models.ReportOrder;

import java.util.List;

public interface IReportOrderService {
    List<ReportOrder> getReportOrder(int storeId, String status, String dateStart, String dateEnd);
}
