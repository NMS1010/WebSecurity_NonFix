<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

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

											<span class="text-dark mb-4 pb-4 iq-border-bottom d-block">${product.description}</span>

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

			<div class="form-group col-lg-12">
				<form method="post">
					<div class="iq-card p-4">
						<div class="mb-3">
							<label>Đánh giá sản phẩm:</label>

							<div class="d-block line-height">
								<span id="rating" class="font-size-20 text-warning"> <input
									type="hidden" id="rating_value" name="rating_value" value="-1">
									<i class="ratings_stars fa fa-star-o" onclick="changeRating(1)"></i>
									<i class="ratings_stars fa fa-star-o" onclick="changeRating(2)"></i>
									<i class="ratings_stars fa fa-star-o" onclick="changeRating(3)"></i>
									<i class="ratings_stars fa fa-star-o" onclick="changeRating(4)"></i>
									<i class="ratings_stars fa fa-star-o" onclick="changeRating(5)"></i>

								</span>
							</div>

							<textarea class="form-control" name="content" rows="5"
								style="line-height: 22px;"></textarea>
						</div>
						<button formaction="<c:url value="/web/book/review/add?orders=${orders.id}&product=${product.id}"/>" class="btn btn-primary mr-2">Lưu
							thay đổi</button>
					</div>
				</form>
			</div>

		</div>
	</div>
</div>

<script>
	function changeRating(rating) {
		var rating_star = document.getElementsByClassName("ratings_stars");
		for (var i = 0; i < rating_star.length; i++) {
			if (i < rating) {
				if (rating_star[i].classList.contains("fa-star-o")) {
					rating_star[i].classList.remove("fa-star-o");
					rating_star[i].classList.add("fa-star");
				}
			} else {
				if (rating_star[i].classList.contains("fa-star")) {
					rating_star[i].classList.add("fa-star-o");
					rating_star[i].classList.remove("fa-star");
				}
			}
		}
		document.getElementById("rating_value").value = rating;
	}
</script>