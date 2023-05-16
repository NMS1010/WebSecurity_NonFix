<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp"%>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
</head>
<body>
<div id="loading">
    <div id="loading-center">
    </div>
</div>
<!-- loader END -->
<!-- Wrapper Start -->
<div class="wrapper">
    <div id="content-page" class="content-page">
        <div class="iq-card">
            <div class="iq-card-header d-flex justify-content-center">
                <div class="iq-header-title">
                    <h4 class="card-title" id="title">${orders.status}</h4>
                </div>
            </div>
            <div class="iq-card-body">
                <div class="table-responsive">
                    <table id="user-list-table" class="table table-striped table-bordered mt-4" role="grid"
                           aria-describedby="user-list-page-info">
                        <thead>
                        <tr class="text-center">
                            <th>STT</th>
                            <th>Tên sản phẩm</th>
                            <th>Mô tả</th>
                            <th>Giá/đơn vị</th>
                            <th>Số lượng</th>
                        </tr>
                        </thead>
                        <tbody>
                        <c:forEach items="${orderDetailsList}" var="orderDetailsList" varStatus="STT" >
                            <tr class="text-center">
                                <td>${STT.index + 1}</td>
                                <td>${orderDetailsList.name}</td>
                                <td>${orderDetailsList.description}</td>
                                <td>${orderDetailsList.price}</td>
                                <td>${orderDetailsList.count}</td>
                            </tr>
                        </c:forEach>
                        </tbody>
                        <h6>Tổng tiền: ${orders.amountFromUser} đồng (đã bao gồm phí vận chuyển)</h6>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
<script type="text/javascript">
    document.getElementById("title").innerText == "delivered" ? document.getElementById("title").innerText = "ĐƠN HÀNG CHI TIẾT (ĐÃ GIAO)" : document.getElementById("title").innerText ="ĐƠN HÀNG CHI TIẾT (ĐANG GIAO)"
    document.getElementById("back").addEventListener('click', function () {
        history.back();
    })
</script>
</body>
</html>
