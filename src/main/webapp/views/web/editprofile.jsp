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
							<h4 class="card-title">Thông tin cá nhân</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<form action="#" method="post" enctype="multipart/form-data">
							<div class="form-group row align-items-center">
								<div class="col-md-12">
									<div class="profile-img-edit">
										<c:url value="/image?fname=${user.avatar}&type=user"
											var="imgAvatar"></c:url>
										<img class="profile-pic" src="${imgAvatar}" alt="profile-pic">
										<div class="p-image">
											<i class="ri-pencil-line upload-button"></i> <input
												class="file-upload" type="file" name="image"
												accept="image/*" />
										</div>
									</div>
								</div>
							</div>
							<div class="row text-center col-lg-12 mb-3">
								<c:if test="${phone_exist==true}">
									<span class="text-danger w-100">Số điện thoại đã được
										đăng ký</span>
								</c:if>
								<c:if test="${id_card_exist==true}">
									<span class="text-danger w-100">CMND/CCCD đã được đăng
										ký</span>
								</c:if>
							</div>
							<div class=" row align-items-center">
								<div class="form-group col-sm-6">
									<label for="fname">Họ:</label> <input name="firstname"
										type="text" class="form-control" id="fname"
										value="${user.firstname}">
								</div>
								<div class="form-group col-sm-6">
									<label class="d-block">Giới tính:</label>
									<div class="custom-control custom-radio custom-control-inline">
										<input type="radio" id="customRadio6" name="sex"
											class="custom-control-input" value="Nam"
											<c:if test="${user.sex == 'Nam'}"> checked </c:if>> <label
											class="custom-control-label" for="customRadio6"> Nam
										</label>
									</div>
									<div class="custom-control custom-radio custom-control-inline">
										<input type="radio" id="customRadio7" name="sex"
											class="custom-control-input" value="Nữ"
											<c:if test="${user.sex == 'Nữ'}"> checked </c:if>> <label
											class="custom-control-label" for="customRadio7"> Nữ </label>
									</div>
								</div>
								<div class="form-group col-sm-6">
									<label for="lname">Tên:</label> <input name="lastname"
										type="text" class="form-control" id="lname"
										value="${user.lastname}">
								</div>
								<div class="form-group col-sm-6">
									<label for="lname">CMND/Căn Cước Công Dân:</label> <input
										name="id_card" type="text" class="form-control" id="id_card"
										value="${user.id_card}">
								</div>
								<div class="form-group col-sm-6">
									<label for="uname">Email:</label> <input name="email"
										type="email" class="form-control" id="uname"
										value="${user.email}" readonly>
								</div>
								<div class="form-group col-sm-6">
									<label for="cname">Số điện thoại:</label> <input name="phone"
										type="text" class="form-control" id="phone"
										value="${user.phone}">
									<!-- </div>
											<div class="form-group col-sm-12">
												<label>Địa chỉ:</label>
												<textarea class="form-control" name="address" rows="5"
													style="line-height: 22px;">
Số 1 Võ Văn Ngân, Thủ Đức
                                          </textarea>
											</div> -->
								</div>
								<button formaction="<c:url value='/web/user/edit/update'/>"
									class="btn btn-primary mr-2 ml-3">Lưu thay đổi</button>
								<button type="reset" class="btn iq-bg-danger">Hủy</button>
							</div>
						</form>
					</div>
				</div>
			</div>
			<div class="col-lg-12">
				<div class="iq-card">
					<div class="iq-card-header d-flex justify-content-between">
						<div class="iq-header-title">
							<h4 class="card-title">Nạp ví MKB</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<form action="#" method="post" enctype="multipart/form-data">
							<div class="form-group">
								<label for="cpass">Số dư trong ví:</label> <span>${user.eWallet}</span>
							</div>
							<div class="form-group">
								<label for="cpass">Số tiền nạp vào:</label> <input
									name="eWallet" type="number" class="form-control" id="cpass"
									value="50000" min="50000" step="1000">
							</div>
							<button formaction="<c:url value="/web/user/edit/eWallet/add"/>"
								class="btn btn-primary mr-2">Nạp</button>
							<button type="reset" class="btn iq-bg-danger">Hủy</button>
						</form>
					</div>
				</div>
			</div>
			<c:if test="${user.password.length() <= 15 }">
				<div class="col-lg-12">
					<div class="iq-card">
						<div class="iq-card-header d-flex justify-content-between">
							<div class="iq-header-title">
								<h4 class="card-title">Đổi mật khẩu</h4>
							</div>
						</div>
						<div class="iq-card-body">
							<form method="post">
								<span class="text-danger d-none" id="caution">Sai mật
									khẩu hiện tại</span>
								<div class="form-group">
									<label for="cpass">Mật khẩu hiện tại:</label> <input
										oninput="currentPass()" name="current_pass" type="Password"
										class="form-control" id="current_pass" value="">
								</div>
								<div class="form-group">
									<label for="npass">Mật khẩu mới:</label> <input name="new_pass"
										oninput="changePass()" type="Password" class="form-control"
										id="new_pass" value="">
								</div>
								<div class="form-group">
									<label for="vpass">Xác nhận mật khẩu:</label> <input
										type="Password" class="form-control" id="re_new_pass" value=""
										oninput="changePass()">
								</div>
								<button id="button_pass"
									formaction="<c:url value="/web/user/edit/updatepassword"/>"
									class="d-none btn btn-primary mr-2">Xác nhận</button>
								<button type="reset" class="btn iq-bg-danger">Hủy</button>
							</form>
						</div>
					</div>
				</div>
			</c:if>
		</div>
	</div>
</div>

<script>

function currentPass()
{
	var cur_pass = document.getElementById("current_pass").value;
	
	if(cur_pass.localeCompare(${user.password}) != 0)
	{
		document.getElementById("caution").classList.remove("d-none");
	}
	else
	{
		document.getElementById("caution").classList.add("d-none");
	}
}

function changePass()
{
	var ne_pass = document.getElementById("new_pass").value;
	var re_pass = document.getElementById("re_new_pass").value;
	
	if(re_pass.localeCompare(ne_pass) == 0)
	{
		document.getElementById("button_pass").classList.remove("d-none");
	}
	else
	{
		document.getElementById("button_pass").classList.add("d-none");
	}
}

</script>