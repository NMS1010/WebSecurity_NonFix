<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row profile-content">
			<div class="col-12 col-md-12 col-lg-4">
				<div class="iq-card">
					<div class="iq-card-body profile-page">
						<div class="profile-header">
							<div class="cover-container text-center">
								<img src="images/user/1.jpg" alt="profile-bg"
									class="rounded-circle img-fluid">
								<div class="profile-detail mt-3">
									<h3>${user.firstname} ${user.lastname}</h3>
								</div>
							</div>
						</div>
					</div>
				</div>
				<div class="iq-card">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center mb-0">
						<div class="iq-header-title">
							<h4 class="card-title mb-0">Thông tin về ${user.lastname}</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<ul class="list-inline p-0 mb-0">
							<li>
								<div class="row align-items-center justify-content-between mb-3">
									<div class="col-sm-6">
										<h6>Địa chỉ</h6>
									</div>
									<div class="col-sm-6">
										<p class="mb-0">[Cập nhật sau]</p>
									</div>
								</div>
							</li>
							<li>
								<div class="row align-items-center justify-content-between mb-3">
									<div class="col-sm-6">
										<h6>Só điện thoại</h6>
									</div>
									<div class="col-sm-6">
										<p class="mb-0">${user.phone}</p>
									</div>
								</div>
							</li>
							<li>
								<div class="row align-items-center justify-content-between mb-3">
									<div class="col-sm-6">
										<h6>Email</h6>
									</div>
									<div class="col-sm-6">
										<p class="mb-0">${user.email}</p>
									</div>
								</div>
							</li>
						</ul>
					</div>
				</div>
			</div>
			<div class="col-12 col-md-12 col-lg-8">
				<div class="iq-card">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center mb-0">
						<div class="iq-header-title">
							<h4 class="card-title mb-0">Danh mục ưa thích</h4>
						</div>
						<div class="iq-card-header-toolbar d-flex align-items-center">
							<div class="dropdown">
								<span class="dropdown-toggle text-primary"
									id="dropdownMenuButton05" data-toggle="dropdown"> <i
									class="ri-more-fill"></i>
								</span>
								<div class="dropdown-menu dropdown-menu-right"
									aria-labelledby="dropdownMenuButton05">
									<a class="dropdown-item" href="#"><i
										class="ri-eye-fill mr-2"></i>View</a> <a class="dropdown-item"
										href="#"><i class="ri-delete-bin-6-fill mr-2"></i>Delete</a> <a
										class="dropdown-item" href="#"><i
										class="ri-pencil-fill mr-2"></i>Edit</a> <a class="dropdown-item"
										href="#"><i class="ri-printer-fill mr-2"></i>Print</a> <a
										class="dropdown-item" href="#"><i
										class="ri-file-download-fill mr-2"></i>Download</a>
								</div>
							</div>
						</div>
					</div>

					<div class="iq-card-body">
						<ul class="perfomer-lists m-0 p-0">
							<li>
								<div class="iq-details mb-2">
									<span class="title">Adventure</span>
									<div class="percentage float-right text-primary">
										95 <span>%</span>
									</div>
									<div class="iq-progress-bar-linear d-inline-block w-100">
										<div class="iq-progress-bar">
											<span class="bg-primary" data-percent="95"></span>
										</div>
									</div>
								</div>
							</li>
							<li>
								<div class="iq-details mb-2">
									<span class="title">Horror</span>
									<div class="percentage float-right text-warning">
										72 <span>%</span>
									</div>
									<div class="iq-progress-bar-linear d-inline-block w-100">
										<div class="iq-progress-bar">
											<span class="bg-warning" data-percent="72"></span>
										</div>
									</div>
								</div>
							</li>
							<li>
								<div class="iq-details mb-2">
									<span class="title">Comic Book</span>
									<div class="percentage float-right text-info">
										75 <span>%</span>
									</div>
									<div class="iq-progress-bar-linear d-inline-block w-100">
										<div class="iq-progress-bar">
											<span class="bg-info" data-percent="75"></span>
										</div>
									</div>
								</div>
							</li>
							<li>
								<div class="iq-details mb-2">
									<span class="title">Biography</span>
									<div class="percentage float-right text-danger">
										70 <span>%</span>
									</div>
									<div class="iq-progress-bar-linear d-inline-block w-100">
										<div class="iq-progress-bar">
											<span class="bg-danger" data-percent="70"></span>
										</div>
									</div>
								</div>
							</li>
							<li>
								<div class="iq-details">
									<span class="title">Mystery</span>
									<div class="percentage float-right text-success">
										80 <span>%</span>
									</div>
									<div class="iq-progress-bar-linear d-inline-block w-100">
										<div class="iq-progress-bar">
											<span class="bg-success" data-percent="80"></span>
										</div>
									</div>
								</div>
							</li>
						</ul>
					</div>
				</div>
				<div class="iq-card">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center mb-0">
						<div class="iq-header-title">
							<h4 class="card-title mb-0">Sách ưa thích</h4>
						</div>
						<div class="iq-card-header-toolbar d-flex align-items-center">
							<div class="dropdown">
								<span class="dropdown-toggle text-primary"
									id="dropdownMenuButton05" data-toggle="dropdown"> <i
									class="ri-more-fill"></i>
								</span>
								<div class="dropdown-menu dropdown-menu-right"
									aria-labelledby="dropdownMenuButton05">
									<a class="dropdown-item" href="#"><i
										class="ri-eye-fill mr-2"></i>View</a> <a class="dropdown-item"
										href="#"><i class="ri-delete-bin-6-fill mr-2"></i>Delete</a> <a
										class="dropdown-item" href="#"><i
										class="ri-pencil-fill mr-2"></i>Edit</a> <a class="dropdown-item"
										href="#"><i class="ri-printer-fill mr-2"></i>Print</a> <a
										class="dropdown-item" href="#"><i
										class="ri-file-download-fill mr-2"></i>Download</a>
								</div>
							</div>
						</div>
					</div>
					<div class="iq-card-body">
						<ul class="perfomer-lists m-0 p-0">
							<li class="d-flex mb-4 align-items-center">
								<div class="user-img img-fluid">
									<img class="img-fluid avatar-50 rounded-circle"
										src="images/user/06.jpg" alt="">
								</div>
								<div class="media-support-info ml-3">
									<h5>Reading on the World</h5>
									<p class="mb-0">Lorem Ipsum is simply dummy test</p>
								</div>
								<div class="iq-card-header-toolbar d-flex align-items-center">
									<span class="text-dark"><b>+$82</b></span>
								</div>
							</li>
							<li class="d-flex mb-4 align-items-center">
								<div class="user-img img-fluid">
									<img class="img-fluid avatar-50 rounded-circle"
										src="images/user/07.jpg" alt="">
								</div>
								<div class="media-support-info ml-3">
									<h5>Little Black Book</h5>
									<p class="mb-0">Lorem Ipsum is simply dummy test</p>
								</div>
								<div class="iq-card-header-toolbar d-flex align-items-center">
									<span class="text-dark"><b>+$90</b></span>
								</div>
							</li>
							<li class="d-flex align-items-center">
								<div class="user-img img-fluid">
									<img class="img-fluid avatar-50 rounded-circle"
										src="images/user/08.jpg" alt="">
								</div>
								<div class="media-support-info ml-3">
									<h5>See the More Story</h5>
									<p class="mb-0">Lorem Ipsum is simply dummy test</p>
								</div>
								<div class="iq-card-header-toolbar d-flex align-items-cener">
									<span class="text-dark"><b>+$85</b></span>
								</div>
							</li>
						</ul>
					</div>
				</div>
				
				<div class="iq-card">
					<div
						class="iq-card-header d-flex justify-content-between align-items-center mb-0">
						<div class="iq-header-title">
							<h4 class="card-title mb-0">Cửa hàng ưa thích</h4>
						</div>
						<div class="iq-card-header-toolbar d-flex align-items-center">
							<div class="dropdown">
								<span class="dropdown-toggle text-primary"
									id="dropdownMenuButton05" data-toggle="dropdown"> <i
									class="ri-more-fill"></i>
								</span>
								<div class="dropdown-menu dropdown-menu-right"
									aria-labelledby="dropdownMenuButton05">
									<a class="dropdown-item" href="#"><i
										class="ri-eye-fill mr-2"></i>View</a> <a class="dropdown-item"
										href="#"><i class="ri-delete-bin-6-fill mr-2"></i>Delete</a> <a
										class="dropdown-item" href="#"><i
										class="ri-pencil-fill mr-2"></i>Edit</a> <a class="dropdown-item"
										href="#"><i class="ri-printer-fill mr-2"></i>Print</a> <a
										class="dropdown-item" href="#"><i
										class="ri-file-download-fill mr-2"></i>Download</a>
								</div>
							</div>
						</div>
					</div>
					<div class="iq-card-body">
						<ul class="perfomer-lists m-0 p-0">
							<li class="d-flex mb-4 align-items-center">
								<div class="user-img img-fluid">
									<img class="img-fluid avatar-50 rounded-circle"
										src="images/user/06.jpg" alt="">
								</div>
								<div class="media-support-info ml-3">
									<h5>Reading on the World</h5>
									<p class="mb-0">Lorem Ipsum is simply dummy test</p>
								</div>
								<div class="iq-card-header-toolbar d-flex align-items-center">
									<span class="text-dark"><b>+$82</b></span>
								</div>
							</li>
							<li class="d-flex mb-4 align-items-center">
								<div class="user-img img-fluid">
									<img class="img-fluid avatar-50 rounded-circle"
										src="images/user/07.jpg" alt="">
								</div>
								<div class="media-support-info ml-3">
									<h5>Little Black Book</h5>
									<p class="mb-0">Lorem Ipsum is simply dummy test</p>
								</div>
								<div class="iq-card-header-toolbar d-flex align-items-center">
									<span class="text-dark"><b>+$90</b></span>
								</div>
							</li>
							<li class="d-flex align-items-center">
								<div class="user-img img-fluid">
									<img class="img-fluid avatar-50 rounded-circle"
										src="images/user/08.jpg" alt="">
								</div>
								<div class="media-support-info ml-3">
									<h5>See the More Story</h5>
									<p class="mb-0">Lorem Ipsum is simply dummy test</p>
								</div>
								<div class="iq-card-header-toolbar d-flex align-items-cener">
									<span class="text-dark"><b>+$85</b></span>
								</div>
							</li>
						</ul>
					</div>
				</div>

			</div>

		</div>
	</div>
</div>