<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp" %>
<c:url value="/vendor/product" var="urlCancel"/>
<html>
<head>
    <title>Title</title>
</head>
<body>
<div class="container-fluid">
    <div class="row">
        <div class="col-sm-12">
            <div class="iq-card">
                <div class="iq-card-header d-flex justify-content-between">
                    <div class="iq-header-title">
                        <h4 class="card-title">Thông tin sản phẩm</h4>
                    </div>
                </div>
                <div class="iq-card-body">
                    <form id="form-product" method="post" enctype="multipart/form-data">
                        <div class="form-group">
                            <label>Tên sách:</label>
                            <input required type="text" class="form-control" placeholder="Nhập tên sách...."
                                name="name" value="${product.name}"
                            >
                        </div>
                        <div class="form-group">
                            <label>Chọn thể loại:</label>
                            <select class="form-control" id="exampleFormControlSelect1" name="categoryId">
                                <option>Thể loại</option>
                                <c:forEach items="${categorise}" var="category">
                                    <option value="${category.id}"
                                        ${category.id == product.categoryId ? "selected" : ""}>
                                            ${category.name}
                                    </option>
                                </c:forEach>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Thêm ảnh:</label>
                            <br>
                            <div class="d-flex">
                                <input class="" type="file" name="image1"
                                       accept="image/*"/>
                                <input class="" type="file" name="image2"
                                       accept="image/*"/>
                                <input class="" type="file" name="image3"
                                       accept="image/*"/>
                                <input class="" type="file" name="image4"
                                       accept="image/*"/>
                            </div>
                            <br>
                            <label>Hình ảnh của sách:</label>
                            <div class="row">
                                <c:forEach items="${images}" var="image">
                                    <div class="col-3">
                                        <div class="profile-img-edit" style="width: 100px; height: 100px">
                                            <c:url
                                                    value="/image?fname=${image.name!=null?image.name:'upload/abc.jpg'}&type=product"
                                                   var="imgUrl"></c:url>
                                            <img class="img-thumbnail" style="width: 100%; height: 100%; object-fit: cover;"
                                                 src="${imgUrl}"
                                                 alt="profile-pic">
                                        </div>
                                    </div>
                                </c:forEach>
                            </div>
                        </div>
                        <div class="row">
                            <div class="form-group col-6">
                                <label>Giá gốc:</label>
                                <input required type="text" class="form-control" placeholder="Nhập giá gốc..."
                                       name="price" value="${product.price}">
                            </div>
                            <div class="form-group col-6">
                                <label>Giá giảm:</label>
                                <input type="text" class="form-control" placeholder="Nhập giá giảm...."
                                       name="promotionalPrice" value="${product.promotionalPrice}">
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="quantity">Số lượng:</label>
                            <button type="button" class="fa fa-minus qty-btn" id="btn-minus"></button>
                            <input required style="width: 10%;" type="text" id="quantity" value="${not empty
                            product.quantity ?
                            product.quantity : 0}"
                                   name="quantity">
                            <button type="button" class="fa fa-plus qty-btn" id="btn-plus"></button>
                        </div>
                        <div class="form-group">
                            <label>Mô tả:</label>
                            <textarea required class="form-control" rows="4"
                                       name="description">${product.description}</textarea>
                        </div>
                        <c:if test="${action == 'add'}">
                            <button formaction="<c:url value="/vendor/product/create"/>"
                                    class="btn btn-primary">Submit</button>
                        </c:if>
                        <c:if test="${action == 'edit'}">
                            <button formaction="<c:url value="/vendor/product/edit?pname=${product.name}"/>"
                                    class="btn btn-warning">Update</button>
                        </c:if>
                        <button onclick="Back(event)" class="btn
                                btn-danger">Cancel</button>

                        <input type="hidden" name="id" value="${product.id}"/>
                        <input type="hidden" name="storeId" value="${product.storeId}">
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<script type="text/javascript">
    document.getElementById("quantity").setAttribute("value", document.getElementById("quantity").value);
    function Back(e) {
        e.preventDefault();
        history.go(-1);
    }
</script>
</body>
</html>
