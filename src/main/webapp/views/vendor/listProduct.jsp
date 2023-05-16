<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>
<c:url value="/vendor/product/category?categoryId=" var="urlProc" />
<c:url value="/vendor/product/delete" var="urlDelete" />
<html>
<head>
<title>Title</title>
</head>
<body>
  <div class="container-fluid">
    <div class="row">
      <div class="col-sm-12">
        <%@include file="/common/info.jsp"%>
        <div class="iq-card">
          <div class="iq-card-header d-flex justify-content-between">
            <div class="iq-header-title">
              <h4 class="card-title">Danh sách sản phẩm</h4>
            </div>
            <div class="iq-card-header-toolbar d-flex align-items-center">
              <a href="<c:url value="/vendor/product/create"/> " class="btn btn-primary"> Thêm sản phẩm </a>
            </div>
          </div>
          <div class="iq-card-body">
            <div class="table-responsive">
              <div class="row">
                <div class="form-group col-sm-6">
                  <div class="form-group">
                    <label>Chọn thể loại:</label> <select class="form-control" name="categoryId" id="selectCate">
                      <option value="0">Tất cả</option>
                      <c:forEach items="${categorise}" var="category">
                        <option value="${category.id}" ${category.id == categoryId ? "selected" : ""}>
                        <a href="#">${category.name}</a>
                        </option>
                      </c:forEach>
                    </select>
                  </div>
                </div>
                <div class="form-group col-sm-6">
                  <label>Tìm kiếm theo tên sách:</label>
                  <div class="iq-card-transparent mb-0">
                    <div class="d-block">
                      <div class="w-100 iq-search-filter">
                        <div class="iq-search-bar search-book d-flex align-items-center">
                          <form action="#" class="searchbox">
                            <input type="text" class="text search-input" placeholder="Nhập tên sản phẩm cần tìm..."
                              id="input-search" name="" value="${search}"
                            >
                          </form>
                          <button id="btn-search" onclick="Search()" class="btn btn-warning search-data ml-2 mb-3">Tìm</button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div class="d-flex" style="margin-top: -40px">
              	<span style="display: inline-block; height: 20px; width: 20px; background-color: red; border-radius: 5px"></span>
              	<p style="margin-left: 3px; line-height:20px">Hết hàng</p>
              </div>
              <table id="table-product" class="data-tables table table-striped table-bordered" style="width: 100%">
                <thead>
                  <tr>
                    <th>No</th>
                    <th>Ảnh</th>
                    <th>Tên sách</th>
                    <th>Loại sách</th>
                    <th>Mô tả</th>
                    <th>Giá gốc</th>
                    <th>Giá giảm</th>
                    <th>Số lượng</th>
                    <th>Đã bán</th>
                    <th>Yêu thích</th>
                    <th>Hành động</th>
                  </tr>
                </thead>
                <tbody id="list-product">
                  <c:forEach items="${products}" var="product" varStatus="index">
                    <tr class="item-product" ${product.quantity == 0 ? "style='color: red;'" : "" }>
                      <td>${index.index + 1 + total*(tag-1)}</td>
                      <td style="width: 100px; min-height: 100px;"><c:url
                          value="/image?fname=${product.getImages().get(0).getName()}&type=product" var="imgUrl"
                        ></c:url> <img class="img-fluid rounded" src="${imgUrl}" alt="pic"
                        style="width: 100%; object-fit: cover;"
                      ></td>
                      <td>${product.name}</td>
                      <td>${product.category.name}</td>
                      <td>${product.description}</td>
                      <td>${product.price}vnd</td>
                      <td>${product.promotionalPrice}vnd</td>
                      <td>${product.quantity}</td>
                      <td>${product.sold}</td>
                      <td>${product.like}</td>
                      <td>
                        <div class="flex align-items-center list-user-action">
                          <a class="iq-bg-primary" data-toggle="tooltip" data-placement="center" title=""
                            data-original-title="Edit"
                            href="<c:url
                                                 value="/vendor/product/edit?pname=${product.name}&storeId=${product.storeId}"/> "
                          > <i class="fa-solid fa-pen-to-square"></i>
                          </a> <a class="iq-bg-primary" data-toggle="modal" data-placement="center"
                            data-target="#modal-delete" title="" data-original-title="Delete" href="#"
                            onclick="GetIdProduct(event)"
                          > <i class="fa-solid fa-trash" id="${product.id}"
                            style="padding: 10px; transform: translate(-17%, -18%);"
                          ></i>
                          </a>
                        </div>
                      </td>
                    </tr>
                  </c:forEach>
                  <input type="hidden" id="productId" value="">
                  <input type="hidden" id="total" name="total" value="">
                  <input type="hidden" id="page" name="page" value="">
                  <input type="hidden" id="maxPageItem" name="maxPageItem" value="">
                  <input type="hidden" id="sortBy" name="sortBy" value="">
                  <input type="hidden" id="sortName" name="sortName" value="">
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- Paging -->
    <div class="row">
      <div class="col-sm-12 col-md-8"></div>
      <div class="col-sm-12 col-md-4">
        <div class="dataTables_paginate paging_simple_numbers">
          <ul class="pagination">
            <li class="paginate_button page-item ${tag <= 1 ? "disabled" : ""}"><a
              href="${pageContext.request.contextPath}/vendor/product/category?categoryId=${categoryId}&index=${tag - 1}"
              class="page-link"
            >Previous </a></li>
            <c:forEach begin="1" end="${endP}" var="i">
              <li class="paginate_button page-item ${i == tag ? "active" : ""}"><a
                href="${pageContext.request.contextPath}/vendor/product/category?categoryId=${categoryId}&index=${i}"
                class="page-link"
              >${i}</a></li>
            </c:forEach>
            <li class="paginate_button page-item ${tag >= endP ? "disabled" : ""}"><a
              href="${pageContext.request.contextPath}/vendor/product/category?categoryId=${categoryId}&index=${tag + 1}"
              class="page-link"
            >Next</a></li>
          </ul>
        </div>
      </div>
    </div>
    <!-- MODAL DELETE -->
    <div class="modal fade" id="modal-delete" tabindex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle"
      aria-hidden="true"
    >
      <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="exampleModalCenterTitle">Xóa sản phẩm</h5>
            <button type="button" class="close" data-dismiss="modal" aria-label="Close">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="modal-body">Bạn chắc chắn xóa sản phẩm này chứ ?</div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-dismiss="modal">Đóng</button>
            <button onclick="Delete()" type="button" class="btn btn-danger" data-dismiss="modal">Xóa</button>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script type="text/javascript">
			function GetIdProduct(e) {
				e.preventDefault();
				const id = e.target.id;
				document.getElementById("productId").value = id;
			}
			function Delete() {
				const id = document.getElementById("productId").value;
				window.location.href = "${urlDelete}?id=" + id;
			}
		</script>
  <script type="text/javascript">
			$('#selectCate').change(function() {
				const categoryId = $("#selectCate option:selected").val();
				window.location.href = "${urlProc}" + categoryId;
			});
		</script>
  <script type="text/javascript">
			function Search() {
				const key = $('#input-search').val();
				const categoryId = $('#selectCate option:selected').val();
				window.location.href = "${urlProc}" + categoryId + "&search="
						+ key;
			}
		</script>
</body>
</html>
