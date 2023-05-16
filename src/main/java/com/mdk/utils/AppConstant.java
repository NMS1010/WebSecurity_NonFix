package com.mdk.utils;

public class AppConstant {

    // role
    public static final String ADMIN = "ADMIN";
    public static final String USER = "USER";
    
    
    // upload
    public static final String UPLOAD_STORE_DIRECTORY = "E:\\upload\\store";
    public static final String UPLOAD_PRODUCT_DIRECTORY = "E:\\upload\\product";
    public static final String UPLOAD_USER_DIRECTORY = "E:\\upload\\user";
    public static final String EXPORT_REPORT = "E:\\report.xls";

    // Session
    public static final String USER_MODEL = "USERMODEL";
    public static final String STORE_MODEL = "STORE";
    public static final String CART = "CART";
    public static final String CART_HEADER = "CART_HEADER";
    public static final String COUNT_CART_HEADER = "COUNT_CART_HEADER";
    public static final String CART_USER = "CART_USER";
    public static final String USER_LOGIN = "USER_LOGIN";

    // message
    public static final String ALERT_UPDATE_SUCCESS = "warning";
    public static final String ALERT_ERROR_SYSTEM = "danger";
    public static final String ALERT_INSERT_SUCCESS = "primary";
    public static final String MESSAGE_INSERT_SUCCESS = "Thêm thành công !!";
    public static final String MESSAGE_UPDATE_SUCCESS = "Chỉnh sửa thành công !!";

    public static final String MESSAGE_ERROR_SYSTEM = "Có lỗi! Vui lòng kiểm tra lại.";
    public static final String MESSAGE_NO_STORE = "Bạn chưa có cửa hàng. Vui lòng tạo !!";
    public static final String MESSAGE_LOGIN_ERROR = "Đăng nhập thất bại !";
    public static final String MESSAGE_LOGIN_NO_PERMISSION = "Bạn không phải ADMIN !";
    public static final String MESSAGE_LOGIN_NO = "Vui lòng đăng nhập !";
    public static final String MESSAGE_INVALID_DATE = "Vui lòng kiểm tra lại ngày !";
    public static final String MESSAGE_EXPORT_SUCCESS = "Xuất báo cáo thành công !";
    public static final String MESSAGE_TRANSACTION_ERROR = "Ví không đủ tiền !";
    public static final String MESSAGE_TRANSACTION_SUCCESS = "Rút tiền thành công !";
    public static final String MESSAGE_EMAIL_EXIST = "Email đã tồn tại !";
    public static final String MESSAGE_PASSWORD_INCORRECT = "Mật khẩu không khớp !";
    public static final String MESSAGE_SINGUP_ERROR = "Đăng ký thất bại !";
    public static final String MESSAGE_VERIFY_FAILED = "Mã xác thực không chính xác !";
    // Paging
    public static final int TOTAL_ITEM_IN_PAGE = 4;

    // Google
    public static String GOOGLE_CLIENT_ID = "740094574805-pa2bc895e0nmd2h00b6njulev52331qg.apps.googleusercontent.com";
    public static String GOOGLE_CLIENT_SECRET = "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";
    public static String GOOGLE_REDIRECT_URI = "http://localhost:8080/eCommerceWebsite/LoginGoogleHandler";
    public static String GOOGLE_LINK_GET_TOKEN = "https://accounts.google.com/o/oauth2/token";
    public static String GOOGLE_LINK_GET_USER_INFO = "https://www.googleapis.com/oauth2/v1/userinfo?access_token=";
    public static String GOOGLE_GRANT_TYPE = "authorization_code";
}
