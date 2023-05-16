<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row">
			<div class="col-sm-12">
				<div class="iq-card">
					<div class="iq-card-header d-flex justify-content-between">
						<div class="iq-header-title">
							<h4 class="card-title">Sách đang theo dõi</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<div class="table-responsive">
							<table id="datatable" class="table">
								<thead>
									<tr>
										<th></th>
										<th>Sách</th>
										<th>Cửa hàng</th>
										<th>Giá bán</th>
										<th>Số sao</th>
										<th>Trạng thái theo dõi</th>
									</tr>
								</thead>
								<tbody>
									<c:forEach items="${userFollowProductList}"
										var="userFollowProduct">
										<tr>
											<td class="d-flex justify-content-center"><a
												href="<c:url value="/web/book/detail?id=${userFollowProduct.product.id}"/>"><c:url
														value="/image?fname=${userFollowProduct.product.getImages().get(0).getName()}&type=product"
														var="imgUrl"></c:url> <img class="img-fluid rounded "
													style="object-fit: contain; height: 75px" src="${imgUrl}"
													alt=""></a></td>
											<td><a style="color: black"
												href="<c:url value="/web/book/detail?id=${userFollowProduct.product.id}"/>">${userFollowProduct.product.name}</a></td>
											<td><a style="color: black"
												href="<c:url value="/web/store/detail?id=${userFollowProduct.product.store.id}"/>">${userFollowProduct.product.store.name}</a></td>
											<td>${userFollowProduct.product.promotionalPrice}</td>
											<td>
												<div class="mb-3 d-block">
													<span class="font-size-20 text-warning"> <c:forEach
															var="i" begin="1" end="5">
															<c:if test="${i <= userFollowProduct.product.rating }">
																<i class="fa fa-star"></i>
															</c:if>

															<c:if test="${i > userFollowProduct.product.rating }">
																<i class="fa fa-star-o"></i>
															</c:if>
														</c:forEach>
													</span>
												</div>
											</td>
											<td><a
												href="<c:url value="/web/following/book/delete?id=${userFollowProduct.id}"/>"
												id="cancel_following_${userFollowProduct.id}" href="#"
												class="text-primary"
												onmouseenter="this.classList.add('text-danger'); this.innerText='Hủy theo dõi'"
												onmouseleave="this.classList.remove('text-danger'); this.innerText='Đang theo dõi'"'>
													Đang theo dõi </a></td>
										</tr>
									</c:forEach>
								</tbody>
							</table>
						</div>
					</div>
				</div>
			</div>
			<div class="col-sm-12">
				<div class="iq-card">
					<div class="iq-card-header d-flex justify-content-between">
						<div class="iq-header-title">
							<h4 class="card-title">Cửa hàng đang theo dõi</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<div class="table-responsive">
							<table id="datatable" class="table table-striped">
								<thead>
									<tr>
										<th></th>
										<th>Cửa hàng</th>
										<th>Sở hữu</th>
										<th>Mô tả</th>
										<th>Số sao</th>
										<th>Trạng thái theo dõi</th>
									</tr>
								</thead>
								<tbody>
									<c:forEach items="${userFollowStoreList}" var="userFollowStore">
										<tr>
										<tr>
											<td class="d-flex justify-content-center"><a
												href="<c:url value="/web/store/detail?id=${userFollowStore.store.id}"/>"><c:url
														value="/image?fname=${userFollowStore.store.getImages().get(0).getName()}&type=store"
														var="imgUrl"></c:url> <img class="img-fluid rounded "
													style="object-fit: contain; height: 75px" src="${imgUrl}"
													alt=""></a></td>
											<td><a style="color: black"
												href="<c:url value="/web/store/detail?id=${userFollowStore.store.id}"/>">${userFollowStore.store.name}</a></td>
											<td><a style="color: black"
												href="<c:url value="/web/user/profile?id=${userFollowStore.store.owner.id}"/>">${userFollowStore.store.owner.firstname}
													${userFollowStore.store.owner.lastname}</a></td>
											<td>${userFollowStore.store.bio}</td>
											<td>
												<div class="mb-3 d-block">
													<span class="font-size-20 text-warning"> <c:forEach
															var="i" begin="1" end="5">
															<c:if test="${i <= userFollowStore.store.rating }">
																<i class="fa fa-star"></i>
															</c:if>

															<c:if test="${i > userFollowStore.store.rating }">
																<i class="fa fa-star-o"></i>
															</c:if>
														</c:forEach>
													</span>
												</div>
											</td>
											<td><a
												href="<c:url value="/web/following/store/delete?id=${userFollowStore.id}"/>"
												id="cancel_following_${userFollowProduct.id}" href="#"
												class="text-primary"
												onmouseenter="this.classList.add('text-danger'); this.innerText='Hủy theo dõi'"
												onmouseleave="this.classList.remove('text-danger'); this.innerText='Đang theo dõi'"'>
													Đang theo dõi </a></td>
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

<script>

function changeFollow(id)
{
	document.getElementById(id).
}

</script>