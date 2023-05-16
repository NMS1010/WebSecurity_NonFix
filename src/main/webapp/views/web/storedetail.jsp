<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row">
			<div class="col-sm-6">
				<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center">
						<h4 class="card-title mb-0">Chi tiết cửa hàng</h4>
					</div>
					<div class="iq-card-body pb-0">
						<div class="description-contens align-items-top row">
							<div class="col-sm-12">
								<div
									class="iq-card-transparent iq-card-block iq-card-stretch iq-card-height">
									<div class="iq-card-body p-0">
										<div class="row align-items-center">
											<div class="col-3">
												<ul id="description-slider-nav"
													class="list-inline p-0 m-0  d-flex align-items-center">
													<c:forEach items="${store.images}" var="image">
														<c:url value="/image?fname=${image.name}&type=store"
															var="imgUrl"></c:url>
														<li><a href="javascript:void(0);"> <img
																src="${imgUrl}" class="img-fluid rounded w-100" alt="">
														</a></li>
													</c:forEach>
												</ul>
											</div>
											<div class="col-9">
												<ul id="description-slider"
													class="list-inline p-0 m-0  d-flex align-items-center">
													<c:forEach items="${store.images}" var="image">
														<c:url value="/image?fname=${image.name}&type=store"
															var="imgUrl"></c:url>
														<li><a href="javascript:void(0);"> <img
																src="${imgUrl}" class="img-fluid rounded w-100" alt="">
														</a></li>
													</c:forEach>
												</ul>
											</div>
										</div>
									</div>
								</div>
							</div>
							<div class="col-md-6">
								<div
									class="iq-card-transparent iq-card-block iq-card-stretch iq-card-height">
									<div class="iq-card-body p-0">
										<h3 class="mb-3">${store.name }</h3>
										<div class="mb-3 d-block">
											<span class="font-size-20 text-warning"> <c:forEach
													var="i" begin="1" end="5">
													<c:if test="${i <= store.rating }">
														<i class="fa fa-star"></i>
													</c:if>

													<c:if test="${i > store.rating }">
														<i class="fa fa-star-o"></i>
													</c:if>
												</c:forEach>
											</span>
										</div>
										<span class="text-dark mb-4 pb-4 iq-border-bottom d-block">${owner.firstname}
											${owner.lastname}</span>
										<div class="text-primary mb-4">
											Mô tả: <span class="text-body">${store.bio}</span>
										</div>
										<div class="mb-3">
											<a
												href="<c:url value="/web/following/store/add?id=${store.id}"/>"
												class="text-body text-center"><span
												class="avatar-30 rounded-circle bg-primary d-inline-block mr-2"><i
													class="ri-heart-fill"></i></span><span>Theo dõi cửa hàng</span></a>
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
			<div class="col-sm-6">
				<div class="iq-card">
					<div
						class="iq-card-header d-flex justify-content-between iq-border-bottom mb-0">
						<div class="iq-header-title">
							<h4 class="card-title">Sản phẩm của của hàng</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<ul class="list-inline p-0 m-0">
							<c:forEach items="${storeProductList}" var="product">
								<li class="checkout-product">
									<div class="row align-items-center">
										<div class="col-sm-3 col-lg-2">
											<div class="row align-items-center">
												<div class="col-sm-9">
													<span class="checkout-product-img"> <a
														href="javascript:void();"><c:url
																value="/image?fname=${product.getImages().get(0).getName()}&type=product"
																var="imgUrl"></c:url> <img
															class="img-fluid rounded w-100 h-100"
															style="object-fit: contain;" src="${imgUrl}" alt=""></a>
													</span>
												</div>
											</div>
										</div>
										<div class="col-sm-3 col-lg-4">
											<div class="checkout-product-details">
												<h5>${product.name}</h5>
												<c:if test="${ product.quantity > 0}">
													<p class="text-success">Còn hàng</p>
												</c:if>
												<c:if test="${ product.quantity <= 0}">
													<p class="text-danger">Hết hàng</p>
												</c:if>
												<div class="price">
													<h5>${product.price}</h5>
												</div>
											</div>
										</div>
										<div class="col-sm-6 col-lg-6">
											<div class="row float-right">
												<form method="post">
													<a href="#"><button
															formaction="<c:url value='/web/cart/item/create?id=${product.id}'/>"
															class="btn btn-primary view-more mr-3">Thêm vào
															giỏ hàng</button></a>
												</form>
											</div>
										</div>
									</div>

								</li>
							</c:forEach>
						</ul>
					</div>
				</div>
			</div>

			<div class="col-lg-12">
				<div class="iq-card p-4">
					<div class="d-block text-center">
						<h4>Đánh giá</h4>
					</div>
					<div class="iq-card-body">
						<div class="table-responsive">
							<table id="user-list-table" class="table table-striped mt-4"
								role="grid" aria-describedby="user-list-page-info">
								<thead>
									<tr>
										<th style="width: 10%">Người dùng</th>
										<th style="width: 90%">Đánh giá</th>
									</tr>
								</thead>
								<tbody>
									<c:forEach items="${reviewList}" var="review">
										<tr>
											<td class="text-center"><c:url
													value="/image?fname=${review.user.avatar}&type=user"
													var="imgAvatar"></c:url> <img
												class="rounded img-fluid avatar-40" src="${imgAvatar}"
												alt="profile">
												<p class="mt-3">${review.user.firstname}
													${review.user.lastname}</p>
												<p class="mt-3">${review.createdAt}</p></td>
											<td>
												<div class="mb-3 d-block">
													<strong>Đơn hàng:</strong>
													<p>${review.product.name}</p>
												</div>
												<div class="mb-3 d-block">
													<span class="font-size-20 text-warning"> <c:forEach
															var="i" begin="1" end="5">
															<c:if test="${i <= review.stars }">
																<i class="fa fa-star"></i>
															</c:if>

															<c:if test="${i > review.stars }">
																<i class="fa fa-star-o"></i>
															</c:if>
														</c:forEach>
													</span>
												</div>
												<p>${review.content}</p>
											</td>
										</tr>
									</c:forEach>
								</tbody>
							</table>
						</div>
						<div class="row justify-content-between mt-3">
							<div id="user-list-page-info" class="col-md-6">
								<span>Showing 1 to 5 of 5 entries</span>
							</div>
							<div class="col-md-6">
								<nav aria-label="Page navigation example">
									<ul class="pagination justify-content-end mb-0">
										<li class="page-item disabled"><a class="page-link"
											href="#" tabindex="-1" aria-disabled="true">Previous</a></li>
										<li class="page-item active"><a class="page-link"
											href="#">1</a></li>
										<li class="page-item"><a class="page-link" href="#">2</a></li>
										<li class="page-item"><a class="page-link" href="#">3</a></li>
										<li class="page-item"><a class="page-link" href="#">Next</a>
										</li>
									</ul>
								</nav>
							</div>
						</div>
					</div>
				</div>
			</div>



		</div>
	</div>
</div>
</div>