<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid checkout-content">
		<div class="row">
			<div id="cart" class="card-block show p-0 col-12">
				<div class="row align-item-center">
					<div class="col-lg-12">
						<c:if test="${empty listCart}">
							<div class="iq-card pt-5 pb-4">
								<div class="col-lg-12 d-flex justify-content-center">
									<img style="width: 20%"
										src="<c:url value="/template/images/emptycart.png"/>" />
								</div>
								<div class="col-lg-12 text-center mb-5">
									<span class="text-second text-uppercase font-size-20">Giỏ
										hàng của bạn đang trống. <a
										href="<c:url value="/web/book/search"/>">Cùng mua sắm nào!</a>
									</span>
								</div>
							</div>
						</c:if>
						<c:forEach items="${listCart}" var="cart">
							<div class="iq-card">
								<div
									class="iq-card-header d-flex justify-content-between iq-border-bottom mb-0">
									<div class="iq-header-title">
										<h4 class="card-title">${cart.store.name}</h4>
									</div>
								</div>
								<div class="iq-card-body">
									<ul class="list-inline p-0 m-0">
										<c:forEach items="${cart.cartItems}" var="cartItem">
											<li class="checkout-product">
												<form method="post">
													<div class="row align-items-center">
														<div class="col-sm-1">
															<span
																class="col-12 p-0 position-relative image-overlap-shadow"
																style="height: 50px;"> <a
																href="javascript:void();"> <c:url
																		value="/image?fname=${cartItem.product.getImages().get(0).getName()}&type=product"
																		var="imgUrl"></c:url> <img
																	class="img-fluid rounded w-100"
																	style="object-fit: contain;" src="${imgUrl}" alt=""></a>
															</span>
														</div>
														<div class="col-sm-5">
															<div class="checkout-product-details">
																<h5>${cartItem.product.name}</h5>
																<p class="text-success">In stock</p>
																<div class="price">
																	<h5>${cartItem.product.promotionalPrice}</h5>
																</div>
															</div>
														</div>


														<div class="col-sm-6">
															<div class="row">
																<div class="col-sm-10">
																	<div class="row align-items-center mt-2">
																		<div class="col-sm-3 col-md-2">
																			<label class="mr-3">Số lượng</label> <label
																				class=" mr-3">${cartItem.count}</label>


																		</div>
																		<div class="col-sm-4 cold-md-4">
																			<label class="mr-3">Thêm sản phẩm</label>
																			<div class="d-flex align-items-center">
																				<c:choose>
																					<c:when test="${cartItem.product.quantity > 0}">
																						<input name="count" class="form-control"
																							style="max-width: 75px; height: 35px" type="number" min="${-1*cartItem.count+1}"
																							max="${cartItem.product.quantity}" step="1" value="1">
																					</c:when>
																					<c:otherwise>
																						<label class="mr-3 text-danger">Hết hàng</label>
																					</c:otherwise>
																				</c:choose>
																				<button
																					formaction="<c:url value='/web/cart/item/create?id=${cartItem.product.id}'/>"
																					class="btn btn-primary view-more ml-2">Thêm</button>
																			</div>
																		</div>
																		<div class="col-sm-5 col-md-6">
																			<span class="product-price">${cartItem.product.promotionalPrice*cartItem.count}</span>
																			<c:set var="cartTotal"
																				value="${cartTotal+cartItem.product.promotionalPrice*cartItem.count}" />
																		</div>
																	</div>
																</div>
																<div class="col-sm-2">
																	<button
																		style="border: none; background-color: transparent"
																		formaction="<c:url value="/web/cart/item/delete?id=${cartItem.id}"/>"
																		class="text-dark font-size-20">
																		<i class="ri-delete-bin-7-fill"></i>
																	</button>
																</div>
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
									<form method="post" class="d-flex justify-content-end">
										<button
											formaction="<c:url value="/web/cart/delivery?cart=${cart.id}"/>"
											id="place-order" href="javascript:void();"
											class="btn btn-primary d-block mt-3 next ">Thanh
											toán</button>
									</form>
								</div>
							</div>

						</c:forEach>
					</div>

				</div>
			</div>
		</div>
	</div>
</div>
