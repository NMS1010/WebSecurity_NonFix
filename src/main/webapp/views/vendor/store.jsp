<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<div class="container-fluid">
    <div class="row">
        <div class="col-lg-12">
            <%@include file="/common/info.jsp"%>
            <div class="iq-edit-list-data">
                <div class="tab-content">
                    <div class="tab-pane fade active show" id="personal-information" role="tabpanel">
                        <div class="iq-card">
                            <div class="iq-card-header d-flex justify-content-between">
                                <div class="iq-header-title">
                                    <h4 class="card-title">Thông tin cửa hàng</h4>
                                </div>
                            </div>
                            <div class="iq-card-body">
                                <c:if test="${count == 0 && action != 'add'}">
                                    <div class="text-center">
                                        <h5>Bạn chưa có cửa hàng.</h5>
                                        <br>
                                        <h5>Ấn tạo của hàng để tạo cửa hàng</h5>
                                        <br>
                                        <a href="<c:url value="/vendor/store/create"/> " class="btn btn-primary btn-lg ">
                                            <i class="fa-solid fa-circle-plus"></i>
                                            Tạo của hàng
                                        </a>
                                    </div>
                                </c:if>
                                <c:if test="${count != 0 || action == 'add'}">
                                    <form action="#" method="post" enctype="multipart/form-data">
                                        <div class="form-group row align-items-center">
                                            <div class="col-md-12">
                                                <div class="profile-img-edit">
                                                    <label>Ảnh đại diện:</label>
                                                    <c:url value="/image?fname=${store.avatar}&type=store"
                                                           var="imgAvatar"></c:url>
                                                    <img class="img-thumbnail" src="${imgAvatar}"
                                                         alt="profile-pic">
                                                    <div class="p-image text-center">
                                                        <a href="#" class="upload-button btn iq-bg-primary">
                                                            <i class="fa-solid fa-pen-to-square"></i>
                                                        </a>
                                                        <input class="file-upload" type="file" name="avatar"
                                                               accept="image/*"/>
                                                    </div>
                                                </div>
                                                <br>
                                                <br>
                                                <label>Thêm ảnh:</label>
                                                <br>
                                                <input class="" type="file" name="image1"
                                                       accept="image/*"/>
                                                <input class="" type="file" name="image2"
                                                       accept="image/*"/>
                                                <input class="" type="file" name="image3"
                                                       accept="image/*"/>
                                                <br>
                                                <br>
                                                <label>Hình ảnh của shop:</label>
                                                <div class="row">
                                                    <c:forEach items="${images}" var="image">
                                                        <div class="col-4">
                                                            <div class="profile-img-edit">
                                                                <c:url value="/image?fname=${image}&type=store"
                                                                       var="imgUrl"></c:url>
                                                                <img class="img-thumbnail" src="${imgUrl}"
                                                                     alt="profile-pic">
                                                            </div>
                                                        </div>
                                                    </c:forEach>
                                                </div>
                                            </div>
                                        </div>
                                        <div class=" row align-items-center">
                                            <c:if test="${action == 'add'}">
                                                <input type="hidden" class="form-control" name="id" value="${count + 1}">
                                            </c:if>
                                            <div class="form-group col-sm-6">
                                                <label for="name">Tên cửa hàng:</label>
                                                <input type="text" class="form-control" id="name" name="name"
                                                       value="${store.name}">
                                            </div>
                                            <div class="form-group col-sm-6">
                                                <label for="owner">Chủ cửa hàng:</label>
                                                <input type="hidden" class="form-control"
                                                       name="ownerId" id="owner"
                                                       value="${ownerId!=null?ownerId:store.ownerID}"
                                                       readonly>
                                                <input type="text" class="form-control"
                                                       name="" id=""
                                                       value="${sessionScope.USERMODEL.firstname} ${sessionScope.USERMODEL.lastname}"
                                                       readonly>
                                            </div>
                                            <div class="form-group col-sm-12">
                                                <label>Mô tả:</label>
                                                <textarea class="form-control" name="bio" rows="5"
                                                          style="line-height:22px;">${store.bio}</textarea>
                                            </div>
                                            <c:if test="${count == 0 || count == null}">
                                                <button formaction="<c:url value="/vendor/store/create"/> "
                                                        class="btn btn-primary ml-3 mr-2">Submit
                                                </button>
                                            </c:if>
                                            <c:if test="${count == 1}">
                                                <button formaction="<c:url value="/vendor/store/edit"/> "
                                                        class="btn btn-warning ml-3 mr-2">Update
                                                </button>
                                            </c:if>

                                            <button type="reset" class="btn btn-danger ml-3">Cancel</button>
                                        </div>
                                    </form>
                                </c:if>
                            </div>
                        </div>
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
