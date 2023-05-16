package com.mdk.controllers.vendor;

import static com.mdk.utils.AppConstant.EXPORT_REPORT;
import static com.mdk.utils.AppConstant.STORE_MODEL;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.DataFormat;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import com.mdk.models.ReportOrder;
import com.mdk.models.Store;
import com.mdk.services.IReportOrderService;
import com.mdk.services.impl.ReportOrderService;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = "/vendor/report-order")
public class ReportOrderHandle extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final int COLUMN_ORDER_ID = 0;
    public static final int COLUMN_DATE_ORDER = 1;
    public static final int COLUMN_STATUS = 2;
    public static final int COLUMN_DELIVERY_ID = 3;
    public static final int COLUMN_DELIVERY_NAME = 4;
    public static final int COLUMN_CATEGORY = 5;
    public static final int COLUMN_PRODUCT_NAME = 6;
    public static final int COLUMN_PRICE = 7;
    public static final int COLUMN_PROMOTION_PRICE = 8;
    public static final int COLUMN_COUNT = 9;
    public static final int COLUMN_TOTAL_PRICE = 10;
    public static final int COLUMN_TOTAL_PRICE_ORDER_ITEM = 11;
    public static final int COLUMN_PRICE_DELIVERY = 12;
    public static final int COLUMN_USER_ORDER = 13;
    public static final int COLUMN_PHONE = 14;
    public static final int COLUMN_ADDRESS = 15;
    private static CellStyle cellStyleFormatDouble = null;
    IReportOrderService reportOrderService = new ReportOrderService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);
        String status = req.getParameter("status");
        String dateStart = req.getParameter("start");
        String dateEnd = req.getParameter("end");
        List<ReportOrder> reportOrder = reportOrderService.getReportOrder(store.getId(), status, dateStart, dateEnd);
        final String excelFilePath = EXPORT_REPORT;
        writeExcel(reportOrder, excelFilePath);
        resp.sendRedirect(req.getContextPath() + 
                "/vendor/order?status="+status+"&start=" + 
                dateStart+"&end="+dateEnd+"&message=export_success&state=success");
    }
    public static void writeExcel(List<ReportOrder> reportOrders, String excelFilePath) throws IOException {
        Workbook workbook = getWorkbook(excelFilePath);
        Sheet sheet = workbook.createSheet("report");
        int rowIndex = 0;
        writeHeader(sheet, rowIndex);
        rowIndex++;
        for (ReportOrder reportOrder : reportOrders) {
            Row row = sheet.createRow(rowIndex);
            writeReport(reportOrder, row);
            rowIndex++;
        }
        int numberOfColumn = sheet.getRow(0).getPhysicalNumberOfCells();
        autosizeColumn(sheet, numberOfColumn);

        createOutputFile(workbook, excelFilePath);
        System.out.println("Done!!!");
    }
    public static Workbook getWorkbook(String excelFilePath) throws  IOException {
        Workbook workbook = null;
        File file = new File(excelFilePath);
        if (!file.exists()) {
            FileOutputStream fileOut = new FileOutputStream(excelFilePath);
            fileOut.close();
        }
        if (excelFilePath.endsWith("xlsx")) {
            workbook = new XSSFWorkbook();
        } else if (excelFilePath.endsWith("xls")) {
            workbook = new HSSFWorkbook();
        } else {
            throw new IllegalArgumentException("The specified file is not Excel file");
        }
        return  workbook;
    }
    private  static  void writeHeader(Sheet sheet, int rowIndex) {
        CellStyle cellStyle = createStyleForHeader(sheet);
        Row row = sheet.createRow(rowIndex);

        Cell cell = row.createCell(COLUMN_ORDER_ID);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Mã đơn hàng");

        cell = row.createCell(COLUMN_DATE_ORDER);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Ngày đặt hàng");

        cell = row.createCell(COLUMN_STATUS);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Trạng thái đơn hàng");

        cell = row.createCell(COLUMN_DELIVERY_ID);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Mã vận chuyển");

        cell = row.createCell(COLUMN_DELIVERY_NAME);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Phương thức vận chuyển");

        cell = row.createCell(COLUMN_CATEGORY);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Thể loại sản phẩm");

        cell = row.createCell(COLUMN_PRODUCT_NAME);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Tên sản phẩm");

        cell = row.createCell(COLUMN_PRICE);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá gốc");

        cell = row.createCell(COLUMN_PROMOTION_PRICE);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá giảm");

        cell = row.createCell(COLUMN_COUNT);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Số lượng");

        cell = row.createCell(COLUMN_TOTAL_PRICE);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Tổng giá tiền");

        cell = row.createCell(COLUMN_TOTAL_PRICE_ORDER_ITEM);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Tổng giá tiền kiện hàng");

        cell = row.createCell(COLUMN_PRICE_DELIVERY);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Giá vận chuyển");

        cell = row.createCell(COLUMN_USER_ORDER);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Tên khách hàng");

        cell = row.createCell(COLUMN_PHONE);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Số điện thoại");

        cell = row.createCell(COLUMN_ADDRESS);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Địa chỉ giao hàng");
    }
    private static void writeReport(ReportOrder reportOrder, Row row) {
        if (cellStyleFormatDouble == null) {
            Workbook workbook = row.getSheet().getWorkbook();
            DataFormat format = workbook.createDataFormat();
            cellStyleFormatDouble = workbook.createCellStyle();
            cellStyleFormatDouble.setDataFormat(format.getFormat("#,##0.00"));
        }
        Cell cell = row.createCell(COLUMN_ORDER_ID);
        cell.setCellValue(reportOrder.getOrderId());

        cell = row.createCell(COLUMN_DATE_ORDER);
        cell.setCellValue(reportOrder.getDateOrder());

        cell = row.createCell(COLUMN_STATUS);
        cell.setCellValue(reportOrder.getStatus());

        cell = row.createCell(COLUMN_DELIVERY_ID);
        cell.setCellValue(reportOrder.getDeliveryId());

        cell = row.createCell(COLUMN_DELIVERY_NAME);
        cell.setCellValue(reportOrder.getDeliveryName());

        cell = row.createCell(COLUMN_CATEGORY);
        cell.setCellValue(reportOrder.getCategoryName());

        cell = row.createCell(COLUMN_PRODUCT_NAME);
        cell.setCellValue(reportOrder.getProductName());

        cell = row.createCell(COLUMN_PRICE);
        cell.setCellValue(reportOrder.getPrice());

        cell = row.createCell(COLUMN_PROMOTION_PRICE);
        cell.setCellValue(reportOrder.getPromotionalPrice());

        cell = row.createCell(COLUMN_COUNT);
        cell.setCellValue(reportOrder.getCount());

        cell = row.createCell(COLUMN_TOTAL_PRICE);
        cell.setCellValue(reportOrder.getTotalPrice());

        cell = row.createCell(COLUMN_TOTAL_PRICE_ORDER_ITEM);
        cell.setCellValue(reportOrder.getTotalPriceOrder());

        cell = row.createCell(COLUMN_PRICE_DELIVERY);
        cell.setCellValue(reportOrder.getPriceDelivery());

        cell = row.createCell(COLUMN_USER_ORDER);
        cell.setCellValue(reportOrder.getUserOrder());

        cell = row.createCell(COLUMN_PHONE);
        cell.setCellValue(reportOrder.getPhone());

        cell = row.createCell(COLUMN_ADDRESS);
        cell.setCellValue(reportOrder.getAddress());
    }
    private static CellStyle createStyleForHeader(Sheet sheet) {
        Font font = sheet.getWorkbook().createFont();
        font.setFontName("Times New Roman");
        font.setBold(true);
        font.setFontHeightInPoints((short) 14); // font size
        font.setColor(IndexedColors.BLACK.getIndex()); // text color

        // Create CellStyle
        CellStyle cellStyle = sheet.getWorkbook().createCellStyle();
        cellStyle.setFont(font);
        cellStyle.setFillForegroundColor(IndexedColors.YELLOW.getIndex());
        cellStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        cellStyle.setBorderBottom(BorderStyle.THIN);
        return cellStyle;
    }
    private static void autosizeColumn(Sheet sheet, int lastColumn) {
        for (int columnIndex = 0; columnIndex < lastColumn; columnIndex++) {
            sheet.autoSizeColumn(columnIndex);
        }
    }
    private static void createOutputFile(Workbook workbook, String excelFilePath) throws IOException {
        try (OutputStream os = new FileOutputStream(excelFilePath)) {
            workbook.write(os);
        }
    }
}
