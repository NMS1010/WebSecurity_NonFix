<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>
<c:url value="/vendor/loadmore-product" var="UrlLoadMoreProduct" />
<c:url value="/vendor/loadmore-customer" var="UrlLoadMoreCustomer" />
<html>
<head>
<title>HomePage</title>
</head>
<body>
		<div class="container-fluid">
				<c:if test="${count == 0}">
						<h5>Bạn chưa có cửa hàng. Làm theo hướng dẫn để tạo cửa hàng.</h5>
						<div class="iq-card-body row">
								<div class="col-12">
										<h5>Bước 1:</h5>
										<img alt="" src="<c:url value="/template/images/guide/1.png"/>" class="img-fluid">
										<div class="mt-3">
												<ol>
														<li>Chọn "Thông tin cửa hàng" trên thanh sidebar</li>
														<li>Ấn nút "Tạo của hàng" để tiến hành tạo cửa hàng</li>
														<li>Số dư trong Ví của cửa hàng của bạn khi giao dịch tiền bán hàng sẽ được chuyển vào đây</li>
														<li>Đây là số dư Ví của bạn, bạn có thể rút tiền từ ví của Store về Ví của mình</li>
												</ol>
										</div>
								</div>
								<div class="col-12">
										<h5>Bước 2:</h5>
										<div class="mt-3">
												<p>Bạn chọn ảnh cho cửa hàng của mình nhé! Nhớ chọn ảnh thật đẹp để thui hút thật nhiều khách hàng .</p>
										</div>
										<img alt="" src="<c:url value="/template/images/guide/3.png"/>" class="img-fluid">
								</div>
								<div class="col-12">
										<div class="mt-3">
												<p>Đặt tên cho cửa hàng của bạn và nhớ ghi mô tả cho cửa hàng ..</p>
										</div>
										<img alt="" src="<c:url value="/template/images/guide/4.png"/>" class="img-fluid">
								</div>
								<div class="col-12">
										<h5>Bước 3:</h5>
										<div class="mt-3">
												<p>Cửa hàng của bạn sau khi được tạo thành công.</p>
										</div>
										<img alt="" src="<c:url value="/template/images/guide/5.png"/>" class="img-fluid"> <img alt=""
												src="<c:url value="/template/images/guide/6.png"/>" class="img-fluid"
										>
								</div>
								<div class="col-12 d-flex">
										<h5>Để hiểu hơn về cách bán hàng trên hệ thống vui lòng tải tệp hướng dẫn sau:</h5>
										<a href="<c:url value="/vendor/download-guide"/>" class="ml-3"> Hướng dẫn <i class="fa-solid fa-download"></i>
										</a>
								</div>
						</div>
				</c:if>
				<c:if test="${count == 1}">
						<div class="row">
								<div class="col-lg-12">
										<div id="carouselExampleIndicators" class="carousel slide" data-ride="carousel" style="height: 250px;">
												<ol class="carousel-indicators">
														<li data-target="#carouselExampleIndicators" data-slide-to="0" class=""></li>
														<li data-target="#carouselExampleIndicators" data-slide-to="1" class="active"></li>
														<li data-target="#carouselExampleIndicators" data-slide-to="2" class=""></li>
														<li data-target="#carouselExampleIndicators" data-slide-to="3" class=""></li>
												</ol>
												<div class="carousel-inner">
														<div class="carousel-item active h-100">
																<c:url value="/image?fname=${store.avatar}&type=store" var="imgAvatar"></c:url>
																<img src="${imgAvatar}" class="d-block w-100 h-100" alt="#" style="object-fit: cover;">
														</div>
														<c:forEach items="${images}" var="image">
																<div class="carousel-item h-100">
																		<c:url value="/image?fname=${image}&type=store" var="img"></c:url>
																		<img src="${img}" class="d-block w-100 h-100" alt="#" style="object-fit: cover;">
																</div>
														</c:forEach>
												</div>
												<a class="carousel-control-prev" href="#carouselExampleIndicators" role="button" data-slide="prev"> <span
														class="carousel-control-prev-icon" aria-hidden="true"
												></span> <span class="sr-only">Previous</span>
												</a> <a class="carousel-control-next" href="#carouselExampleIndicators" role="button" data-slide="next"> <span
														class="carousel-control-next-icon" aria-hidden="true"
												></span> <span class="sr-only">Next</span>
												</a>
										</div>
								</div>
								<div class="col-lg-12">
										<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
												<div class="iq-card-header d-flex justify-content-between align-items-center position-relative">
														<div class="iq-header-title">
																<h4 class="card-title mb-0">Sản phẩm của Shop</h4>
														</div>
												</div>
												<div class="iq-card-body">
														<div class="row" id="list-product">
																<c:forEach items="${products}" var="product">
																		<div class="product col-sm-6 col-md-4 col-lg-3">
																				<div class="iq-card iq-card-block iq-card-stretch iq-card-height browse-bookcontent">
																						<div class="iq-card-body p-0">
																								<div>
																										<div class="col-12 p-0 position-relative image-overlap-shadow" style="height: 150px;">
																												<a href=""> <c:url
																																value="/image?fname=${product.getImages().get(0).getName()}&type=product" var="imgUrl"
																														></c:url> <img class="img-fluid rounded w-100 h-100" style="object-fit: contain;"
																														src="${imgUrl}" alt=""
																												>
																												</a>
																												<div class="view-book">
																														<a
																																href="<c:url value="/vendor/product/edit?pname=${product.name}&storeId=${product.storeId}"/>"
																																class="btn btn-sm btn-white"
																														> View Book </a>
																												</div>
																										</div>
																										<div class="col-12 mt-3">
																												<div class="mb-2">
																														<h6 class="mb-1">${product.name}</h6>
																														<p class="font-size-13 line-height mb-1">${product.description}</p>
																														<div class="d-block line-height">
																																<span id="rating" class="font-size-11 text-warning"> <c:forEach var="i" begin="1"
																																				end="5"
																																		>
																																				<c:if test="${i <= product.rating }">
																																						<i class="fa fa-star"></i>
																																				</c:if>
																																				<c:if test="${i > product.rating }">
																																						<i class="fa fa-star-o"></i>
																																				</c:if>
																																		</c:forEach>
																																</span>
																														</div>
																												</div>
																												<div class="price d-flex">
																														<span class="pr-1 old-price font-size-13">${product.price}</span> <br>
																														<h6>
																																<b>${product.promotionalPrice}</b>
																														</h6>
																												</div>
																										</div>
																								</div>
																						</div>
																				</div>
																		</div>
																</c:forEach>
														</div>
														<div class="iq-card-header-toolbar d-flex justify-content-center align-items-center">
																<button onclick="LoadMoreProduct()" class="btn btn-sm btn-primary view-more">View More</button>
														</div>
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
								<div class="col-lg-12">
										<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
												<div class="iq-card-header d-flex justify-content-between align-items-center position-relative">
														<div class="iq-header-title">
																<h4 class="card-title mb-0">Các khách hàng theo dõi</h4>
														</div>
												</div>
												<div class="iq-card-body">
														<div class="row" id="">
																<table id="list-all-order" class="table table-striped table-bordered mt-4" role="grid"
																		aria-describedby="user-list-page-info"
																>
																		<thead>
																				<tr>
																						<th>Thông tinh khách hàng</th>
																						<th>Trạng thái</th>
																				</tr>
																		</thead>
																		<tbody id="list-customer">
																				<c:forEach items="${followStores}" var="followStore">
																						<tr class="customer">
																								<td>
																										<div class="d-flex align-items-center mb-1">
																												<c:choose>
																														<c:when test="${review.user.avatar != null}">
																																<c:url value="/image?fname=${followStore.user.avatar}&type=user" var="imgAvatar"></c:url>
																														</c:when>
																														<c:otherwise>
																																<c:url value='/template/images/default-avatar.png' var="imgAvatar" />
																														</c:otherwise>
																												</c:choose>
																												<img class="rounded-circle img-fluid avatar-40" src="${imgAvatar}" alt="profile">
																												<p class="mt-3 ml-1 mr-3">${followStore.user.firstname}${followStore.user.lastname}</p>
																												<div>
																													<p class="mt-3 ml-1 mr-3">Giới tính: ${followStore.user.sex}</p>
																													<p class="mt-3 ml-1 mr-3">Số điện thoại: ${followStore.user.phone}</p>
																													<p class="mt-3 ml-1 mr-3">Email: ${followStore.user.email}</p>
																												</div>
																										</div>
																								</td>
																								<td>Đang theo dõi</td>
																						</tr>
																				</c:forEach>
																		</tbody>
																</table>
														</div>
														<div class="iq-card-header-toolbar d-flex justify-content-center align-items-center">
																<button onclick="LoadMoreCustomer()" class="btn btn-sm btn-primary view-more">View More</button>
														</div>
												</div>
										</div>
								</div>
						</div>
				</c:if>
		</div>
		<script>
			function LoadMoreProduct() {
				const amount = document.getElementsByClassName("product").length;
				$.ajax({
					url : "${UrlLoadMoreProduct}",
					type : "get",
					data : {
						exist : amount
					},
					success : function(data) {
						$("#list-product").append(data);
					},
					error : function(xhr) {

					}
				})
			}
			function LoadMoreCustomer() {
				const amount = document.getElementsByClassName("customer").length;
				$.ajax({
					url : "${UrlLoadMoreCustomer}",
					type : "get",
					data : {
						exist : amount
					},
					success : function(data) {
						$("#list-customer").append(data);
					},
					error : function(xhr) {

					}
				})
			}
		</script>
</body>
</html>
