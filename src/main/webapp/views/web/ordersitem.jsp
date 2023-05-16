<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row">
			<div class="col-lg-12">

				<div class="iq-card">
					<div class="iq-card-header d-flex justify-content-between">
						<div class="iq-header-title">
							<h4 class="card-title">Thông tin khách hàng</h4>
						</div>
					</div>

					<div class="iq-card-body">
						<div class="row mt-3">
							<div class="col-md-6">
								<div class="form-group">
									<label><strong>Tên khác hàng:</strong></label> <span>${orders.user.firstname}
										${orders.user.lastname}</span>
								</div>
							</div>
							<div class="col-md-6">
								<div class="form-group">
									<label><strong>CMND/Căn Cước Công Dân:</strong></label> <span>${orders.user.id_card}</span>
								</div>
							</div>
							<div class="col-md-6">
								<div class="form-group">
									<label><strong>Số điện thoại di động:</strong></label>
									${orders.phone}
								</div>
							</div>
							<div class="col-md-6">
								<div class="form-group">
									<label><strong>Địa chỉ:</strong></label> ${orders.address}
								</div>
							</div>
							<div class="col-md-6">
								<div class="form-group">
									<label><strong>Dịch vụ giao hàng:</strong></label>
									${orders.delivery.name}
								</div>
							</div>
							<div class="col-md-6">
								<div class="form-group">
									<label><strong>Tổng tiền thanh toán:</strong></label>
									${orders.amountFromUser}
								</div>
							</div>
						</div>

					</div>
				</div>
			</div>
			<div class="col-lg-12">
				<div class="iq-card">
					<div class="iq-card-body">
						<ul class="list-inline p-0 m-0">
							<c:forEach items="${orders.ordersItem}" var="item">
								<li class="checkout-product">
									<form method="post">
										<div class="row align-items-center">
											<div class="col-sm-1">
												<span
													class="col-12 p-0 position-relative image-overlap-shadow"
													style="height: 50px;"> <a href="javascript:void();">
														<c:url
															value="/image?fname=${item.product.getImages().get(0).getName()}&type=product"
															var="imgUrl"></c:url> <img
														class="img-fluid rounded w-100"
														style="object-fit: contain;" src="${imgUrl}" alt="">
												</a>
												</span>
											</div>
											<div class="col-sm-5">
												<div class="checkout-product-details">
													<h5>${item.product.name}</h5>
													<div class="mb-3 d-block">
														<span class="font-size-20 text-warning"> <c:forEach
																var="i" begin="1" end="5">
																<c:if test="${i <= item.product.rating }">
																	<i class="fa fa-star"></i>
																</c:if>

																<c:if test="${i > item.product.rating }">
																	<i class="fa fa-star-o"></i>
																</c:if>
															</c:forEach>
														</span>
													</div>
													<div class="price">
														<h5>${item.product.promotionalPrice}x${item.count}</h5>
													</div>
												</div>
											</div>


											<div class="col-sm-6">
												<div class="row">
													<div class="col-sm-12">
														<div class="row align-items-center mt-2">
															<div class="col-sm-12 col-md-12">
																<span class="product-price float-right">${item.product.promotionalPrice*item.count}</span>
																<c:set var="cartTotal"
																	value="${cartTotal+item.product.promotionalPrice*item.count}" />
															</div>
														</div>
													</div>
												</div>
											</div>
											<div class="col-sm-12">
												<div class="d-flex justify-content-between">
													<c:if test="${orders.status == 'delivered'}">
														<a
															href="<c:url value="/web/book/review?orders=${orders.id}&product=${item.product.id}"/>"
															id="place-order" href="javascript:void();"
															class="btn btn-primary d-block mt-3 next ">Đánh giá
															sản phẩm</a>
													</c:if>
													<c:if test="${orders.status != 'delivered'}">
													<p class="text-danger mt-3">Chưa thể đánh giá sản phẩm</p>
													</c:if>
												</div>
											</div>
										</div>
									</form>
								</li>
							</c:forEach>
						</ul>
					</div>
					<div class="iq-card-body">
						<div class="d-flex justify-content-between">
							<span class="text-dark"><strong>Tổng cộng</strong></span> <span
								class="text-dark"><strong>${cartTotal}</strong></span>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>