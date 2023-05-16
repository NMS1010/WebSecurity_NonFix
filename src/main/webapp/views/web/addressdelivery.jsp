<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>



<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid checkout-content">
		<div class="row">
			<div id="address" class="card-block show p-0 col-12">
				<form method="post" class="row align-item-center">
					<div class="col-lg-8">

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
											<label><strong>Tên khác hàng:</strong></label> <span>${user.firstname}
												${user.lastname}</span>
										</div>
									</div>
									<div class="col-md-6">
										<div class="form-group">
											<label><strong>CMND/Căn Cước Công Dân:</strong></label> <span>${user.id_card}</span>
										</div>
									</div>
									<div class="col-md-6">
										<div class="form-group">
											<label><strong>Số điện thoại di động:*</strong></label> <input
												name="phone" type="text" class="form-control" name="mno"
												required="" value="${user.phone}">
										</div>
									</div>
									<div class="col-md-6">
										<div class="form-group">
											<label><strong>Địa chỉ:*</strong></label> <input
												name="address" type="text" class="form-control"
												name="houseno" required="" value="Địa chỉ">
										</div>
									</div>
									<div class="col-md-6">
										<div class="form-group">
											<label><strong>Dịch vụ giao hàng:*</strong></label> <select
												name="deliveryId" id="SelectDelivery" class="form-control"
												onchange="changeDeliveryPrice()">
												<c:forEach items="${listDelivery}" var="delivery">
													<option value="${delivery.id}">${delivery.name}-
														${delivery.description}</option>
												</c:forEach>
											</select>
										</div>
									</div>
								</div>

							</div>
						</div>
					</div>
					<div class="col-lg-4">
						<div class="iq-card">
							<div class="iq-card-body">
								<h4 class="mb-2">Đơn hàng</h4>
								<div class="iq-card-body">
									<c:set var="cartTotal" value="${0}" />
									<c:forEach items="${cart.cartItems}" var="cartItem">
										<c:set var="cartTotal"
											value="${cartTotal+cartItem.product.promotionalPrice*cartItem.count}" />
										<div class="d-flex justify-content-between mb-1">
											<span style="max-width: 80%">${cartItem.product.name} -
												${cartItem.product.promotionalPrice} - x${cartItem.count}</span> <span>${cartItem.product.promotionalPrice*cartItem.count}</span>
										</div>
									</c:forEach>
									<div class="d-flex justify-content-between">
										<span class="text-dark"><strong>Tổng cộng đơn
												hàng</strong></span> <span class="text-dark">${cartTotal}</span>
									</div>
									<hr>
									<div class="d-flex justify-content-between">
										<span class="text-dark">Phí ship:</span> <span
											id="DeliveryPrice" class="text-dark"></span>
									</div>
									<hr>
									<div class="d-flex justify-content-between">
										<span class="text-dark"><strong>Tổng cộng:</strong></span> <strong><span
											id="TotalWithDelivery" class="text-dark"></span></strong>
									</div>
									<div class="d-flex justify-content-between">
										<span class="text-dark"><strong>Ví MKB</strong></span> <span
											class="text-dark">${user.eWallet}</span>
									</div>
								</div>
								<div class="iq-card-body">
									<c:choose>
										<c:when test="${user.eWallet >= cartTotal }">
											<button formaction="<c:url value="/web/order/create"/>"
												class="btn btn-primary d-block mt-1 next col-lg-12">Thanh
												toán</button>
										</c:when>
										<c:otherwise>
											<div class="d-block mt-1 next col-lg-12">Ví MKB không đủ
												để thanh toán</div>
										</c:otherwise>
									</c:choose>
								</div>

							</div>
						</div>
					</div>
				</form>
			</div>
		</div>
	</div>
</div>
<script>
var list_of_stocks= {
		<c:forEach items="${listDelivery}" var="delivery" varStatus="loop">
		'${delivery.id}' : ${delivery.price}${!loop.last ? ',' : ''}
		</c:forEach>
		};
function changeDeliveryPrice()
{
	document.getElementById("DeliveryPrice").innerHTML = list_of_stocks[document.getElementById("SelectDelivery").value];
	document.getElementById("TotalWithDelivery").innerHTML = ${cartTotal} + list_of_stocks[document.getElementById("SelectDelivery").value];
	
}

window.onload = function(){
	changeDeliveryPrice()
};
</script>