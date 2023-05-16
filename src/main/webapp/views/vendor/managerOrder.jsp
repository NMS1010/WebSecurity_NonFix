<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp" %>
<c:url value="/vendor/order/manager?status=" var="UrlOrderManager"/>
<c:url value="/vendor/order" var="UrlOrder"/>
<c:url value="/vendor/report-order?status=" var="UrlReport"/>
<html>
<head>
    <title>Title</title>
</head>
<body>
<div class="container-fluid">
    <div class="row">
        <div class="col-lg-12">
            <%@include file="/common/info.jsp"%>
            <div class="iq-card">
                <div class="iq-card-body p-0">
                    <div class="iq-edit-list">
                        <ul class="iq-edit-profile d-flex nav nav-pills">
                            <li class="col-md-2 p-0">
                                <a class="nav-link ${statusResp=='all'?'active':''}"
                                   href="<c:url value="/vendor/order/manager?status=all"/>">
                                    Tất cả
                                </a>
                            </li>
                            <li class="col-md-2 p-0">
                                <a class="nav-link ${statusResp=='not-processed'?'active':''}"
                                   href="<c:url value="/vendor/order/manager?status=not-processed"/> ">
                                    Chờ xử lý
                                </a>
                            </li>
                            <li class="col-md-2 p-0">
                                <a class="nav-link ${statusResp=='shipped'?'active':''}"
                                   href="<c:url value="/vendor/order/manager?status=shipped"/> ">
                                    Đang giao
                                </a>
                            </li>
                            <li class="col-md-2 p-0">
                                <a class="nav-link ${statusResp=='delivered'?'active':''}"
                                   href="<c:url value="/vendor/order/manager?status=delivered"/> ">
                                    Đã giao
                                </a>
                            </li>
                            <li class="col-md-2 p-0">
                                <a class="nav-link ${statusResp=='cancelled'?'active':''}"
                                   href="<c:url value="/vendor/order/manager?status=cancelled"/> ">
                                    Đơn hủy
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-lg-12">
            <div class="iq-card-transparent mb-0">
                <div class="d-block">
                    <div class="w-100 iq-search-filter">
                        <div class="iq-search-bar search-book d-flex align-items-center">
                            <label>Ngày đặt hàng:</label>
                            <form style="margin-left: 10px">
                                <input type="date" class="search-input"
                                    id="date-start" required value="${dateStart}"
                                >
                            </form>
                            <span style="height: 45px; font-size: 20px; margin-left: 10px;">-</span>
                            <form style="margin-left: 10px">
                                <input type="date" class="search-input"
                                       id="date-end" required value="${dateEnd}"
                                       onchange="CheckDate()"
                                >
                            </form>
                            <button onclick="Search()" class="btn btn-warning search-data ml-2 mb-3">Tìm</button>
                            <button onclick="Report()" class="btn btn-danger search-data ml-2 mb-3">Xuất</button>
                            <c:if test="${not empty success}">
                                <a href="<c:url value="/vendor/download-report"/> "
                                   class="text-dark" style="display: block; margin-left: 10px; margin-bottom: 12px;">
                                    Tải báo cáo
                                    <i class="fa-solid fa-download"></i>
                                </a>
                            </c:if>
                        </div>
                    </div>
                </div>
            </div>
            <div class="iq-edit-list-data">
                <div class="tab-content">
                    <div class="tab-pane fade active show" id="allorder" role="tabpanel">
                        <div class="iq-card">
                            <div class="iq-card-header d-flex justify-content-between">
                                <div class="iq-header-title">
                                    <h4 class="card-title">Tổng số đơn hàng: ${count}</h4>
                                </div>
                            </div>
                            <div class="iq-card-body">
                                <div class="table-responsive">
                                    <table id="list-all-order" class="table table-striped table-bordered mt-4"
                                           role="grid" aria-describedby="user-list-page-info">
                                        <thead>
                                        <tr>
                                            <th>Mã đơn hàng</th>
                                            <th>Người mua</th>
                                            <th>Vận chuyển</th>
                                            <th>Ngày đặt</th>
                                            <th>Trạng thái</th>
                                            <th>Thao tác</th>
                                        </tr>
                                        </thead>
                                        <tbody>
                                        <c:forEach items="${orders}" var="order">
                                            <tr>
                                                <td>${order.id}</td>
                                                <td>${order.user.firstname} ${order.user.lastname}</td>
                                                <td>${order.delivery.name}</td>
                                                <td>${order.createdAt}</td>
                                                <c:if test="${order.status == 'not-processed'}">
                                                    <td>Chờ xử lý</td>
                                                </c:if>
                                                <c:if test="${order.status == 'shipped'}">
                                                    <td>Đang giao</td>
                                                </c:if>
                                                <c:if test="${order.status == 'delivered'}">
                                                    <td>Đã giao</td>
                                                </c:if>
                                                <c:if test="${order.status == 'cancelled'}">
                                                    <td>Đã hủy</td>
                                                </c:if>
                                                <td>
                                                    <a class="iq-bg-primary" data-toggle="tooltip"
                                                       data-placement="center"
                                                       title="" data-original-title="Edit"
                                                       href="<c:url
                                                       value="/vendor/order/detail?action=edit&orderId=${order.id}"/> ">
                                                        Xem chi tiết
                                                    </a>
                                                </td>
                                            </tr>
                                        </c:forEach>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="row">
        <div class="col-sm-12 col-md-8">

        </div>
        <div class="col-sm-12 col-md-4">
            <div class="dataTables_paginate paging_simple_numbers">
                <ul class="pagination">
                    <li class="paginate_button page-item ${tag <= 1 ? "disabled" : ""}">
                        <a href="${pageContext.request.contextPath}/vendor/order/manager?status=${statusResp}&index=${tag - 1}"
                           class="page-link">Previous
                        </a>
                    </li>
                    <c:forEach begin="1" end="${endP}" var="i">
                        <li class="paginate_button page-item ${i == tag ? "active" : ""}">
                            <a href="${pageContext.request.contextPath}/vendor/order/manager?status=${statusResp}&index=${i}"
                               class="page-link">${i}</a>
                        </li>
                    </c:forEach>
                    <li class="paginate_button page-item ${tag >= endP ? "disabled" : ""}">
                        <a href="${pageContext.request.contextPath}/vendor/order/manager?status=${statusResp}&index=${tag + 1}"
                           class="page-link">Next</a>
                    </li>
                </ul>
            </div>
        </div>
    </div>
</div>
<script>
    const status = $("#statusOrder").innerText;
    var newStatus = "";
    if (status == "not-processed") {
        newStatus = "Chờ xử lý";
    } else if (status == "shipped") {
        newStatus = "Đang giao";
    } else if (status == "delivered") {
        newStatus = "Đã giao";
    } else if (status == "cancelled") {
        newStatus = "Đã hủy";
    }
    $("#statusOrder").innerText = newStatus;
</script>
<script>
    function Report() {
        const dateStart = $("#date-start").val()
        const dateEnd = $("#date-end").val();

        if(CheckDate()) {
            window.location.href = "${UrlReport}" + "${statusResp}" + "&start=" + dateStart + "&end=" + dateEnd;
        } else {
            window.location.href = "${UrlOrder}?message=invalid_date"
        }
    }

    function Search() {
        const dateStart = $("#date-start").val()
        const dateEnd = $("#date-end").val();

        if (CheckDate()) {
            window.location.href = "${UrlOrderManager}" + "${statusResp}" + "&start=" + dateStart + "&end=" + dateEnd;
        } else {
            window.location.href = "${UrlOrder}?message=invalid_date"
        }
    }
    function CheckDate() {
        const dateStart = new Date($("#date-start").val())
        const dateEnd = new Date($("#date-end").val());
        if (dateStart == "Invalid Date" || dateEnd == "Invalid Date" || dateStart > dateEnd) {
            return false;
        }
        return true;
    }
</script>
</body>
</html>
