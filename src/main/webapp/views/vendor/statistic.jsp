<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<c:url value="/vendor/statistic?topseller=" var="urlTop" />
<c:url value="/vendor/statistic/loadchart" var="urlLoadChartRevenue" />
<c:url value="/vendor/transaction/loadchart" var="urlLoadChartTransaction" />
<c:url value="/vendor/review/loadchart" var="urlLoadChartRating" />
<c:url value="/vendor/loadTopProduct" var="urlLoadTopProduct" />
<html>
<head>
<title>Title</title>
</head>
<body>
		<div class="container-fluid">
				<%@include file="/common/info.jsp"%>
				<div class="row">
						<div class="col-md-6 col-lg-3">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-body">
												<div class="d-flex align-items-center">
														<div class="rounded-circle iq-card-icon d-flex align-items-center justify-content-center bg-primary">
																<i class="fa-solid fa-users"></i>
														</div>
														<div class="text-left ml-3">
																<h2 class="mb-0">
																		<span class="counter">${totalCustomer}</span>
																</h2>
																<h5 class="">Customer</h5>
														</div>
												</div>
										</div>
								</div>
						</div>
						<div class="col-md-6 col-lg-3">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-body">
												<div class="d-flex align-items-center">
														<div class="rounded-circle iq-card-icon d-flex align-items-center justify-content-center bg-danger">
																<i class="fa-solid fa-book"></i>
														</div>
														<div class="text-left ml-3">
																<h2 class="mb-0">
																		<span class="counter">${totalProduct}</span>
																</h2>
																<h5 class="">Books</h5>
														</div>
												</div>
										</div>
								</div>
						</div>
						<div class="col-md-6 col-lg-3">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-body">
												<div class="d-flex align-items-center">
														<div class="rounded-circle iq-card-icon d-flex align-items-center justify-content-center bg-warning">
																<i class="fa-solid fa-cart-shopping"></i>
														</div>
														<div class="text-left ml-3">
																<h2 class="mb-0">
																		<span class="counter">${totalSale}</span>
																</h2>
																<h5 class="">Sale</h5>
														</div>
												</div>
										</div>
								</div>
						</div>
						<div class="col-md-6 col-lg-3">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-body">
												<div class="d-flex align-items-center">
														<div class="rounded-circle iq-card-icon d-flex align-items-center justify-content-center bg-info">
																<i class="fa-solid fa-satellite-dish"></i>
														</div>
														<div class="text-left ml-3">
																<h2 class="mb-0">
																		<span class="counter">${totalOrder}</span>
																</h2>
																<h5 class="">Orders</h5>
														</div>
												</div>
										</div>
								</div>
						</div>
						<div class="col-lg-12">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-header position-relative mb-0 similar-detail">
												<div class="iq-header-title d-flex">
														<h4 class="card-title mb-0 d-flex align-items-center">Thống kê doanh thu</h4>
														<div style="margin-left: 16px;">
																<select class="form-control" name="" id="selectYear">
																		<c:forEach begin="0" end="2" var="i">
																				<option value="${year - i}">Năm: ${year - i}</option>
																		</c:forEach>
																</select>
														</div>
												</div>
										</div>
										<div class="iq-card-body">
												<div id="chartContainer" style="height: 370px; width: 100%;"></div>
										</div>
								</div>
						</div>
						<div class="col-lg-12">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-header position-relative mb-0 similar-detail">
												<div class="iq-header-title d-flex">
														<h4 class="card-title mb-0 d-flex align-items-center">Chi tiết giao dịch</h4>
														<div style="margin-left: 16px;">
																<select class="form-control" name="" id="selectYearTransaction">
																		<c:forEach begin="0" end="2" var="i">
																				<option value="${year - i}">Năm: ${year - i}</option>
																		</c:forEach>
																</select>
														</div>
												</div>
										</div>
										<div class="iq-card-body">
												<div id="chartTransaction" style="height: 370px; width: 100%;"></div>
										</div>
								</div>
						</div>
						<div class="col-lg-12">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-header position-relative mb-0 similar-detail">
												<div class="iq-header-title d-flex">
														<h4 class="card-title mb-0 d-flex align-items-center">Đánh giá của khách hàng</h4>
												</div>
										</div>
										<div class="iq-card-body">
												<div id="chartRating" style="height: 370px; width: 100%;"></div>
										</div>
								</div>
						</div>
						<div class="col-lg-12">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-header position-relative mb-0 similar-detail">
												<div class="iq-header-title d-flex">
														<h4 class="card-title mb-0 d-flex align-items-center">Top sách bán chạy</h4>
														<div style="margin-left: 16px;">
																<select class="form-control" name="top" id="selectedTop">
																		<option ${top == 4 ? "selected" : ""} value="4">Top 4</option>
																		<option ${top == 8 ? "selected" : ""} value="8">Top 8</option>
																		<option ${top == 16 ? "selected" : ""} value="16">Top 16</option>
																</select>
														</div>
												</div>
										</div>
										<div class="iq-card-body">
												<div class="row" id="list-product"></div>
										</div>
								</div>
						</div>
						<div class="col-lg-12">
								<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
										<div
												class="iq-card-header d-flex justify-content-between align-items-center position-relative mb-0 similar-detail"
										>
												<div class="iq-header-title">
														<h4 class="card-title mb-0 d-flex align-items-center">Đơn hàng mới nhất</h4>
												</div>
										</div>
										<div class="iq-card-body">
												<div class="table-responsive">
														<table id="list-all-order" class="table table-striped table-bordered mt-4" role="grid"
																aria-describedby="user-list-page-info"
														>
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
																						<td>${order.user.firstname}${order.user.lastname}</td>
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
																						<td><a class="iq-bg-primary" data-toggle="tooltip" data-placement="center" title=""
																								data-original-title="Edit"
																								href="<c:url
                                                       value="/vendor/order/detail?action=edit&orderId=${order.id}"/> "
																						> Xem chi tiết </a></td>
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
		<script src="https://canvasjs.com/assets/script/canvasjs.min.js"></script>
		<script type="text/javascript">
    function loadTopProduct(top) {
        $.ajax({
            url: "${urlLoadTopProduct}",
            type: "get",
            data: {
                top
            },
            success: function (data) {
                $("#list-product").empty();
                $("#list-product").append(data);
            },
            error: function (xhr) {
                console.log("Error")
            }
        })
    }
    // chart revenue
    function loadChartRevenue(data) {
        const chart = new CanvasJS.Chart("chartContainer", {
        	exportEnabled: true,
            animationEnabled: true,
            title: {
                text: "Thống kê doanh thu của năm",
                fontFamily: "tahoma",
            },
            axisX: {
                title: "Tháng"
            },
            axisY: {
                title: "Doanh thu (VND)",
                includeZero: true
            },
            toolTip: {
                shared: true
            },
            legend: {
                cursor:"pointer",
            },
            data: [{
                type: "column",
                yValueFormatString: "#,##0.0# VND",
                dataPoints: data,
            }]
        });
        chart.render();
    }
    function loadDataRevenueOfEachYear(year) {
        $.ajax({
            url: "${urlLoadChartRevenue}",
            type: "get",
            data: {
                year
            },
            success: function (data) {
                console.log(data);
                loadChartRevenue(data);
            },
            error: function (xhr) {
                console.log("Error")
            }
        })
    }
    // chart transaction
    function loadChartTransaction(data) {
        const chart = new CanvasJS.Chart("chartTransaction", {
        		exportEnabled: true,
            animationEnabled: true,
            title: {
                text: "Chi tiết các giao dịch",
                fontFamily: "tahoma",
            },
            axisX: {
                title: "Tháng"
            },
            axisY: {
                title: "(VND)",
                includeZero: true
            },
            toolTip: {
                shared: true
            },
            legend: {
                cursor:"pointer",
            },
            data: [{
                type: "column",
                name: "Nạp",
                yValueFormatString: "#,##0.0# VND",
                dataPoints: data[0],
            },{
                type: "column",
                name: "Rút",
                yValueFormatString: "#,##0.0# VND",
                dataPoints: data[1],
            }]
        });
        chart.render();
    }
    function loadDataTransactionOfEachYear(year) {
        $.ajax({
            url: "${urlLoadChartTransaction}",
            type: "get",
            data: {
                year
            },
            success: function (data) {
                console.log(data);
                loadChartTransaction(data);
            },
            error: function (xhr) {
                console.log("Error")
            }
        })
    }
    function loadChartRating(data) {
    	const chart = new CanvasJS.Chart("chartRating", {
    		theme: "light2", // "light1", "dark1", "dark2"
    		exportEnabled: true,
    		animationEnabled: true,
    		title: {
    			text: "Đánh giá của khách hàng"
    		},
    		data: [{
    			type: "pie",
    			toolTipContent: "<b>{label}</b>: {y}%",
    			indexLabelFontSize: 16,
    			indexLabel: "{label} - {y}%",
    			dataPoints: data
    		}]
    	});
    	chart.render();
    }
    function loadDataRating() {
    	$.ajax({
    		url: "${urlLoadChartRating}",
    		type: "get",
    		data: {},
    		success: function (data) {
                console.log(data);
                loadChartRating(data);
            },
            error: function (xhr) {
                console.log("Error")
            }
    	})
    }
    $("#selectedTop").change(function () {
        const top = $("#selectedTop option:selected").val();
        loadTopProduct(top);
    })
    $("#selectYear").change(function () {
        const year = $("#selectYear").val();
        loadDataRevenueOfEachYear(year);
    })
    $("#selectYearTransaction").change(function () {
        const year = $("#selectYearTransaction").val();
        loadDataTransactionOfEachYear(year);
    })
    function loadPage() {
    		if (window.location.pathname.includes("statistic")) {
    			const year = $("#selectYear").val();
    	        const top = $("#selectedTop option:selected").val();
    	        loadDataRevenueOfEachYear(year);
    	        loadDataTransactionOfEachYear(year);
    	        loadDataRating();
    	        loadTopProduct(top);
    		}
    }
    loadPage();
    
</script>
</body>
</html>
