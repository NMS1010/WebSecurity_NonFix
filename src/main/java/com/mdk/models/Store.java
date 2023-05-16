
package com.mdk.models;

import java.util.ArrayList;
import java.util.List;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.DataFormat;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Workbook;

public class Store extends AbstractModel<Store> {
	private static CellStyle cellStyleFormatDouble = null;
	private String name;
	private String bio;
	private int ownerID;
	private boolean isOpen;
	private String avatar;
	private int rating;
	private double eWallet;
	private User owner;
	private List<ImageStore> images;
	private String nameUser;

	public String getNameUser() {
		return nameUser;
	}

	public void setNameUser(String nameUser) {
		this.nameUser = nameUser;
	}

	public int getTotal() {
		return total;
	}

	public void setTotal(int total) {
		this.total = total;
	}

	private int total;

	public List<ImageStore> getImages() {
		return images;
	}

	public void setImages(List<ImageStore> images) {
		this.images = images;
	}

	public double geteWallet() {
		return eWallet;
	}

	public void seteWallet(double eWallet) {
		this.eWallet = eWallet;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getBio() {
		return bio;
	}

	public void setBio(String bio) {
		this.bio = bio;
	}


	public int getOwnerID() {
		return ownerID;
	}

	public void setOwnerID(int ownerID) {
		this.ownerID = ownerID;
	}

	public boolean isOpen() {
		return isOpen;
	}

	public void setOpen(boolean isOpen) {
		this.isOpen = isOpen;
	}

	public String getAvatar() {
		return avatar;
	}

	public void setAvatar(String avatar) {
		this.avatar = avatar;
	}

	public int getRating() {
		return rating;
	}

	public void setRating(int rating) {
		this.rating = rating;
	}

	public User getOwner() {
		return owner;
	}

	public void setOwner(User owner) {
		this.owner = owner;
	}

	public static List<HeaderElementExcel> getColumns() {
		List<HeaderElementExcel> list = new ArrayList<>();
		list.add(new HeaderElementExcel(0, "Tên cửa hàng"));
		list.add(new HeaderElementExcel(1, "Giới thiệu"));
		list.add(new HeaderElementExcel(2, "Mã chủ cửa hàng"));
		list.add(new HeaderElementExcel(3, "Chủ cửa hàng"));
		list.add(new HeaderElementExcel(4, "Đánh giá"));
		list.add(new HeaderElementExcel(5, "Ví tiền"));
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
		cell.setCellValue(name);

		cell = row.createCell(1);
		cell.setCellValue(bio);

		cell = row.createCell(2);
		cell.setCellValue(ownerID);

		cell = row.createCell(3);
		cell.setCellValue(avatar);  //Thực chất là tên chủ cửa hàng

		cell = row.createCell(4);
		cell.setCellValue(rating);

		cell = row.createCell(5);
		cell.setCellValue(eWallet);
	}
}

