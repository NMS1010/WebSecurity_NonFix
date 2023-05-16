package com.mdk.models;


import java.util.ArrayList;
import java.util.List;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.DataFormat;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Workbook;

public class Orders extends AbstractModel<Orders> {
    private static CellStyle cellStyleFormatDouble = null;
    private int userId;
    private int storeId;
    private int deliveryId;
    private String address;
    private String phone;
    private String status;
    private Double amountFromUser;
    private Double amountToStore;
    private Double amountToGD;
    private User user;
    private Store store;
    private Delivery delivery;
    private List<OrdersItem> ordersItem;
    private String nameOwner;
    private String nameDelivery;

    public String getNameOwner() {
        return nameOwner;
    }

    public void setNameOwner(String nameOwner) {
        this.nameOwner = nameOwner;
    }

    public String getNameDelivery() {
        return nameDelivery;
    }

    public void setNameDelivery(String nameDelivery) {
        this.nameDelivery = nameDelivery;
    }

    public Delivery getDelivery() {
        return delivery;
    }

    public void setDelivery(Delivery delivery) {
        this.delivery = delivery;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Store getStore() {
        return store;
    }

    public void setStore(Store store) {
        this.store = store;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public int getStoreId() {
        return storeId;
    }

    public void setStoreId(int storeId) {
        this.storeId = storeId;
    }

    public int getDeliveryId() {
        return deliveryId;
    }

    public void setDeliveryId(int deliveryId) {
        this.deliveryId = deliveryId;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Double getAmountFromUser() {
        return amountFromUser;
    }

    public void setAmountFromUser(Double amountFromUser) {
        this.amountFromUser = amountFromUser;
    }

    public Double getAmountToStore() {
        return amountToStore;
    }

    public void setAmountToStore(Double amountToStore) {
        this.amountToStore = amountToStore;
    }

    public Double getAmountToGD() {
        return amountToGD;
    }

    public void setAmountToGD(Double amountToGD) {
        this.amountToGD = amountToGD;
    }

	public List<OrdersItem> getOrdersItem() {
		return ordersItem;
	}

	public void setOrdersItem(List<OrdersItem> ordersItem) {
		this.ordersItem = ordersItem;
	}
    public static List<HeaderElementExcel> getColumns() {
        List<HeaderElementExcel> list = new ArrayList<>();
        list.add(new HeaderElementExcel(0, "Tên người mua hàng"));
        list.add(new HeaderElementExcel(1, "Tên đơn vị vận chuyển"));
        list.add(new HeaderElementExcel(2, "Địa chỉ khách hàng"));
        list.add(new HeaderElementExcel(3, "Số điện thoại"));
        list.add(new HeaderElementExcel(4, "Giá thành"));
        return list;
    }

    @Override
    public void writeReport(Row row) {
        if (cellStyleFormatDouble == null) {
            Workbook workbook = row.getSheet().getWorkbook();
            DataFormat format = workbook.createDataFormat();
            cellStyleFormatDouble = workbook.createCellStyle();
            cellStyleFormatDouble.setDataFormat(format.getFormat("#,##0.00"));
        }

        Cell cell = row.createCell(0);
        cell.setCellValue(nameOwner);

        cell = row.createCell(1);
        cell.setCellValue(nameDelivery);

        cell = row.createCell(2);
        cell.setCellValue(address);

        cell = row.createCell(3);
        cell.setCellValue(phone);

        cell = row.createCell(4);
        cell.setCellValue(amountFromUser);
    }

}
