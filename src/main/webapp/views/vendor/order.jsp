<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp" %>
<c:url value="/vendor/order/manager?status=all" var="urlBack"/>
<html>
<head>
    <title>Title</title>
</head>
<body>
<div class="col-lg-12">
    <div class="iq-card">
        <div class="iq-card-header d-flex justify-content-between">
            <div class="iq-header-title">
                <h4 class="card-title">Thông tin đơn hàng</h4>
            </div>
        </div>
        <div class="iq-card-body">
            <form method="post">
                <div class="row mt-3">
                    <div class="col-md-12">
                        <div class="form-group">
                            <label>Tên cửa hàng: *</label>
                            <input type="text" class="form-control"
                                   name="storeName"
                                   value="${ordersDetail.storeName}"
                                   required="" readonly>
                        </div>
                    </div>
                    <div class="col-md-7">
                        <div class="form-group">
                            <label>Tên người nhận: *</label>
                            <input type="text" class="form-control"
                                   name="userName"
                                   value="${ordersDetail.userName}"
                                   required="" readonly>
                        </div>
                    </div>
                    <div class="col-md-5">
                        <div class="form-group">
                            <label>Số điện thoại: *</label>
                            <input type="text" class="form-control"
                                   name="phone"
                                   value="${ordersDetail.phone}"
                                   required="" readonly>
                        </div>
                    </div>
                    <c:forEach items="${ordersDetail.products}" var="product">
                        <div class="col-md-7">
                            <div class="form-group">
                                <label>Tên sản phẩm: *</label>
                                <input type="text" class="form-control"
                                       name="productName"
                                       value="${product.name}"
                                       required="" readonly>
                            </div>
                        </div>
                        <div class="col-md-2">
                            <div class="form-group">
                                <label>Số lượng: *</label>
                                <input type="text" class="form-control"
                                       name="count"
                                       value="${product.count}"
                                       required="" readonly>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="form-group">
                                <label>Giá tiền: *</label>
                                <input type="text" class="form-control"
                                       name="price"
                                       value="${product.price}"
                                       required="" readonly>
                            </div>
                        </div>
                    </c:forEach>

                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Vân chuyển: *</label>
                            <input type="text" class="form-control"
                                   name="delivery"
                                   value="${ordersDetail.deliveryName}"
                                   required="" readonly>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Đia chỉ: *</label>
                            <input type="text" class="form-control"
                                   name="address"
                                   value="${ordersDetail.address}"
                                   required="" readonly>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Ngày đặt: *</label>
                            <input type="text" class="form-control"
                                   name="createdAt"
                                   value="${ordersDetail.createdAt}"
                                   required="" readonly>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label for="status">Trạng thái: *</label>
                            <select class="form-control" id="status" name="status">
                                <option value="not-processed"
                                ${ordersDetail.status == "not-processed" ? "selected" : ""}>Chờ xử lý</option>
                                <option value="shipped"
                                ${ordersDetail.status == "shipped" ? "selected" : ""}>Đang giao</option>
                                <option value="delivered"
                                ${ordersDetail.status == "delivered" ? "selected" : ""}>Đã giao</option>
                                <option value="cancelled"
                                ${ordersDetail.status == "cancelled" ? "selected" : ""}>Đã hủy</option>
                            </select>
                        </div>
                    </div>

                    <div class="col-md-1">
                        <button id="savenddeliver" formaction="<c:url
                        value="/vendor/order/update?orderId=${ordersDetail.ordersId}"/> "
                                class="btn btn-primary">Save</button>
                    </div>
                    <div class="col-md-1">
                        <button onclick="Back(event)" id="back" class="btn btn-danger">Back</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>
<script>
    function Back(e) {
        e.preventDefault();
        history.go(-1);
    }
</script>
</body>
</html>
