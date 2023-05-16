<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>
<html>
<head>
<title>HomePage</title>
</head>
<body>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row">
			<div class="col-sm-12">
				<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center">
						<h4 class="card-title mb-0">Mô tả sản phẩm</h4>
					</div>
					<div class="iq-card-body pb-0">
						<div class="description-contens align-items-top row">
							<div class="col-md-6">
								<div
									class="iq-card-transparent iq-card-block iq-card-stretch iq-card-height">
									<div class="iq-card-body p-0">
										<div class="row align-items-center">
											<div class="col-3">
												<ul id="description-slider-nav"
													class="list-inline p-0 m-0  d-flex align-items-center">
													<c:forEach items="${product.images}" var="image">
														<c:url value="/image?fname=${image.name}&type=product"
															var="imgUrl"></c:url>
														<li><a href="javascript:void(0);"> <img
																src="${imgUrl}" class="img-fluid rounded w-100" alt="">
														</a></li>
													</c:forEach>
												</ul>
											</div>
											<div class="col-9">
												<ul id="description-slider"
													class="list-inline p-0 m-0 d-flex align-items-center">
													<c:forEach items="${product.images}" var="image">
														<c:url value="/image?fname=${image.name}&type=product"
															var="imgUrls"></c:url>
														<li><a href="javascript:void(0);"> <img
																src="${imgUrls}" class="img-fluid rounded w-100" alt="">
														</a></li>
													</c:forEach>
												</ul>
											</div>
										</div>
									</div>
								</div>
							</div>
							<div class="col-md-6">
								<form method="post">
									<div
										class="iq-card-transparent iq-card-block iq-card-stretch iq-card-height">
										<div class="iq-card-body p-0">
											<h3 class="mb-3">${product.name}</h3>
											<div
												class="price d-flex align-items-center font-weight-500 mb-2">
												<!-- <span class="font-size-20 pr-2 old-price">99.000</span> -->
												<span class="font-size-24 text-dark">${product.promotionalPrice}</span>
											</div>
											<div class="mb-3 d-block">
												<span class="font-size-20 text-warning"> <c:forEach
														var="i" begin="1" end="5">
														<c:if test="${i <= product.rating }">
															<i class="fa fa-star"></i>
														</c:if>

														<c:if test="${i > product.rating }">
															<i class="fa fa-star-o"></i>
														</c:if>
													</c:forEach>
												</span>
											</div>
											<div class="mb-3 d-flex align-items-center">
												<c:choose>
													<c:when test="${product.quantity > 0}">
														<label class="mr-3">Số lượng</label>
														<input name="count" class="form-control"
															style="max-width: 75px" type="number" min="1"
															max="${product.quantity}" step="1" value="1">
													</c:when>
													<c:otherwise>
														<label class="mr-3 text-danger">Hết hàng</label>
													</c:otherwise>
												</c:choose>
											</div>
											<span class="text-dark mb-4 d-block">${product.description}</span>
											<span class="text-dark mb-4 pb-4 iq-border-bottom d-block">Cửa
												hàng: <c:if test="${not empty sessionScope.USER_MODEL}">
													<a
														href="<c:url value="/web/store/detail?id=${product.store.id}"/>"
														class="text-primary">${product.store.name}</a>
												</c:if> <c:if test="${empty sessionScope.USER_MODEL}">
													<a
														href="<c:url value="/home/store/detail?id=${product.store.id}"/>"
														class="text-primary">${product.store.name}</a>
												</c:if>
											</span>
											<div class="mb-4 d-flex align-items-center">
												<button
													formaction="<c:url value='/web/cart/item/create?id=${product.id}'/>"
													class="btn btn-primary view-more mr-2">Thêm vào
													giỏ hàng</button>
											</div>
											<div class="mb-3">
												<a
													href="<c:url value='/web/following/book/add?id=${product.id}'/>"
													class="text-body text-center"><span
													class="avatar-30 rounded-circle bg-primary d-inline-block mr-2"><i
														class="ri-heart-fill"></i></span><span>Theo dõi sản phẩm</span></a>
											</div>
										</div>
									</div>
								</form>
							</div>
						</div>
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
							<table id="user-list-table" class="table mt-4" role="grid"
								aria-describedby="user-list-page-info">
								<thead>
									<tr>
										<th class="text-center" style="width: 10%">Người dùng</th>
										<th class="text-center" style="width: 90%">Đánh giá</th>
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
</body>
</html>
