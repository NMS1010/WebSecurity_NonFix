<%@ page contentType="text/html;charset=UTF-8" language="java"%>
<%@include file="/common/taglib.jsp"%>
<div id="loading">
	<div id="loading-center"></div>
</div>
<!-- loader END -->
<!-- Wrapper Start -->

<!-- Sidebar  -->
<!-- TOP Nav Bar -->

<!-- TOP Nav Bar END -->
<!-- Page Content  -->
<div id="content-page" class="content-page"
	style="margin-left: 0; padding-top: 16p !important; padding: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">

		<div class="row">

			<div class="col-sm-12">
				<div class="iq-card">

					<div class="iq-card-body">

						<div id="carouselExampleIndicators" class="carousel slide"
							data-ride="carousel">
							<ol class="carousel-indicators">
								<li data-target="#carouselExampleIndicators" data-slide-to="0"
									class="active"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="1"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="2"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="3"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="4"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="5"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="6"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="7"></li>
								<li data-target="#carouselExampleIndicators" data-slide-to="8"></li>
							</ol>
							<div class="carousel-inner">
								<div class="carousel-item active">
									<img src="<c:url value="/template/images/ads/1.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/2.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/3.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/4.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/5.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/6.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/7.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/8.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
								<div class="carousel-item">
									<img src="<c:url value="/template/images/ads/9.jpg"/>"
										class="d-block w-100" alt="#">
								</div>
							</div>
							<a class="carousel-control-prev"
								href="#carouselExampleIndicators" role="button"
								data-slide="prev"> <span class="carousel-control-prev-icon"
								aria-hidden="true"></span> <span class="sr-only">Previous</span>
							</a> <a class="carousel-control-next"
								href="#carouselExampleIndicators" role="button"
								data-slide="next"> <span class="carousel-control-next-icon"
								aria-hidden="true"></span> <span class="sr-only">Next</span>
							</a>
						</div>
					</div>
				</div>
			</div>
			<div class="col-lg-12">
				<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center position-relative">
						<div class="iq-header-title">
							<h4 class="card-title mb-0">Sách hiện có</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<div class="row">
							<c:forEach items="${productList}" var="product">
								<div class="product col-sm-6 col-md-4 col-lg-2">
									<div
										class="iq-card iq-card-block iq-card-stretch iq-card-height browse-bookcontent">
										<div class="iq-card-body p-0">
											<div>
												<div
													class="col-12 p-0 position-relative image-overlap-shadow"
													style="height: 150px;">
													<a href=""> <c:url
															value="/image?fname=${product.getImages().get(0).getName()}&type=product"
															var="imgUrl"></c:url> <img
														class="img-fluid rounded w-100 h-100"
														style="object-fit: contain;" src="${imgUrl}" alt="">
													</a>
													<div class="view-book">
														<c:if test="${not empty sessionScope.USER_MODEL}">
															<a
																href="<c:url value ='/web/book/detail?id=${product.id}'/>"
																class="btn btn-sm btn-white"> View Book </a>
														</c:if>
														<c:if test="${empty sessionScope.USER_MODEL}">
															<a
																href="<c:url value ='/home/book/detail?id=${product.id}'/>"
																class="btn btn-sm btn-white"> View Book </a>
														</c:if>
													</div>
												</div>
												<div class="col-12 mt-3">
													<div class="mb-2">
														<h6 class="mb-1">${product.name}</h6>
														<p class="font-size-13 line-height mb-1">${product.description}</p>

														<div class="d-block line-height">
															<span id="rating" class="font-size-11 text-warning">
																<c:forEach var="i" begin="1" end="5">
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
														<span class="pr-1 old-price font-size-13">${product.price}</span>
														<br>
														<h6>
															<b>${product.promotionalPrice}</b>
														</h6>
													</div>


													<div class="iq-product-action">
														<form method="post">
															<button
																style="border: none; background-color: transparent"
																formaction="<c:url value='/web/cart/item/create?id=${product.id}'/>"
																href="#">
																<i class="ri-shopping-cart-2-fill text-primary"></i>
															</button>

															<a
																href="<c:url value='/web/following/book/add?id=${product.id}'/>"
																class="ml-2"><i class="ri-heart-fill text-danger"></i></a>
														</form>
													</div>
												</div>
											</div>
										</div>
									</div>
								</div>
							</c:forEach>
						</div>
					</div>
				</div>
			</div>



			<div class="col-lg-12">
				<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center position-relative mb-0 trendy-detail">
						<div class="iq-header-title">
							<h4 class="card-title mb-0">Sách bán chạy</h4>
						</div>
					</div>
					<div class="iq-card-body trendy-contens">
						<ul id="trendy-slider" class="list-inline p-0 mb-0 row">
							<c:forEach items="${topSellerList}" var="product">
								<li class="col-md-8">
									<div class="d-flex align-items-center">
										<div class="col-6 p-0 position-relative image-overlap-shadow">
											<a href="javascript:void();"><c:url
													value="/image?fname=${product.getImages().get(0).getName()}&type=product"
													var="imgUrl"></c:url> <img class="img-fluid rounded w-100"
												style="object-fit: contain; height: 25vh" src="${imgUrl}"
												alt=""></a>
											<div class="view-book">
												<c:if test="${not empty sessionScope.USER_MODEL}">
													<a
														href="<c:url value ='/web/book/detail?id=${product.id}'/>"
														class="btn btn-sm btn-white"> View Book </a>
												</c:if>
												<c:if test="${empty sessionScope.USER_MODEL}">
													<a
														href="<c:url value ='/home/book/detail?id=${product.id}'/>"
														class="btn btn-sm btn-white"> View Book </a>
												</c:if>
											</div>
										</div>
										<div class="col-7">
											<div class="mb-2">
												<h6 class="mb-1">${product.name}</h6>
												<div class="d-block">
													<span class="font-size-13 text-warning"> <c:forEach
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
											</div>
											<div class="price d-flex align-items-center">
												<div class="price d-flex">
													<span class="pr-1 old-price font-size-13">${product.price}</span>
													<br>
													<h6>
														<b>${product.promotionalPrice}</b>
													</h6>
												</div>
											</div>
											<div class="iq-product-action">
												<form method="post">
													<button style="border: none; background-color: transparent"
														formaction="<c:url value='/web/cart/item/create?id=${product.id}'/>"
														href="#">
														<i class="ri-shopping-cart-2-fill text-primary"></i>
													</button>
													<a
														href="<c:url value='/web/following/book/add?id=${product.id}'/>"
														class="ml-2"><i class="ri-heart-fill text-danger"></i></a>
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
				<div class="iq-card iq-card-block iq-card-stretch iq-card-height">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center position-relative">
						<div class="iq-header-title">
							<h4 class="card-title mb-0">Sách được ưa thích</h4>
						</div>
					</div>
					<div class="iq-card-body favorites-contens">
						<ul id="favorites-slider" class="list-inline p-0 mb-0 row">
							<c:forEach items="${topRatingList}" var="product">
								<li class="col-md-8">
									<div class="d-flex justify-content-between align-items-center ">
										<div class="col-5 p-0 position-relative image-overlap-shadow">
											<a href="javascript:void();"> <c:url
													value="/image?fname=${product.getImages().get(0).getName()}&type=product"
													var="imgUrl"></c:url> <img
												class="img-fluid rounded w-100 img-responsive"
												style="object-fit: contain; height: 25vh" src="${imgUrl}"
												alt="">
											</a>
											<div class="view-book">
												<c:if test="${not empty sessionScope.USER_MODEL}">
													<a
														href="<c:url value ='/web/book/detail?id=${product.id}'/>"
														class="btn btn-sm btn-white"> View Book </a>
												</c:if>
												<c:if test="${empty sessionScope.USER_MODEL}">
													<a
														href="<c:url value ='/home/book/detail?id=${product.id}'/>"
														class="btn btn-sm btn-white"> View Book </a>
												</c:if>
											</div>
										</div>
										<div class="col-7">
											<div class="mb-2">
												<h6 class="mb-1">${product.name}</h6>
												<div class="d-block">
													<span class="font-size-13 text-warning"> <c:forEach
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
											</div>
											<div class="price d-flex align-items-center">
												<div class="price d-flex">
													<span class="pr-1 old-price font-size-13">${product.price}</span>
													<br>
													<h6>
														<b>${product.promotionalPrice}</b>
													</h6>
												</div>
											</div>
											<div class="iq-product-action">
												<form method="post">
													<button style="border: none; background-color: transparent"
														formaction="<c:url value='/web/cart/item/create?id=${product.id}'/>"
														href="#">
														<i class="ri-shopping-cart-2-fill text-primary"></i>
													</button>
													<a
														href="<c:url value='/web/following/book/add?id=${product.id}'/>"
														class="ml-2"><i class="ri-heart-fill text-danger"></i></a>
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

		</div>
	</div>
</div>


<!-- Wrapper END -->
<!-- Footer -->