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
<%--Hide--%>
<input type="number" value="${total}" id="total">
<input type="number" value="${male}" id="male">
<input type="number" value="${female}" id="female">

<div id="loading">
  <div id="loading-center">
  </div>
</div>
<!-- loader END -->
<!-- Wrapper Start -->
<div class="wrapper">
  <div id="content-page" class="content-page">
    <div class="container-fluid">
      <div class="row">
        <div class="col-md-12">
          <div class="iq-card iq-card-block iq-card-stretch iq-card-height">
            <div class="iq-card-header d-flex justify-content-center align-items-center text-center">
              <div class="iq-header-title">
                <h4>QUẢN LÝ NGƯỜI DÙNG THÂN THIẾT</h4>
              </div>
            </div>
          </div>
        </div>
        <div class="col-md-12">
          <div class="iq-card iq-card-block iq-card-stretch iq-card-height">
            <div id="chartContainerCircle" style="height: 370px; width: 100%;"></div>
          </div>
        </div>
        <div class="col-md-12">
          <div class="iq-card iq-card-block iq-card-stretch iq-card-height">
            <div id="chartContainerColumn" style="height: 370px; width: 100%;"></div>
          </div>
        </div>
        <div class="col-md-12">
          <div class="iq-card iq-card-block iq-card-stretch iq-card-height">
            <div id="chartContainerLine" style="height: 370px; width: 100%;"></div>
          </div>
        </div>
        <div class="col-sm-12">
          <div class="iq-card">
            <div class="iq-card-header d-flex justify-content-center">
              <div class="iq-header-title">
                <h4 class="card-title">Top 10 người dùng mua hàng nhiều nhất</h4>
              </div>
            </div>            <div class="iq-card-body">
              <div class="table-responsive">
                <table id="user-list-table" class="table table-striped table-bordered mt-4" role="grid"
                       aria-describedby="user-list-page-info">
                  <thead>
                  <tr class="text-center">
                    <th>STT</th>
                    <th>Họ và tên đệm</th>
                    <th>Tên</th>
                    <th>CMND/CCCD</th>
                    <th>Email</th>
                    <th>Phone</th>
                    <th>Tổng đơn hàng</th>
                  </tr>
                  </thead>
                  <tbody>
                  <c:forEach items="${userList}" var="users" varStatus="STT" >
                    <tr class="text-center">
                      <td>${STT.index + 1 }</td>
                      <td>${users.lastname }</td>
                      <td>${users.firstname }</td>
                      <td>${users.id_card }</td>
                      <td>${users.email }</td>
                      <td>${users.phone }</td>
                      <td>${users.totalOrders }</td>
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
</div>
<script src="https://canvasjs.com/assets/script/canvasjs.min.js"></script>
<script>
  window.onload = function() {
    const arrEachMonth = ${arrEachMonth}
    const arrByMonth = ${arrByMonth}
    const arrEachMonthInLastYear = ${arrEachMonthInLastYear}
    const total = $("#total").val();
    const male = $("#male").val();
    const female = $("#female").val();
    var chart1 = new CanvasJS.Chart("chartContainerCircle", {
      animationEnabled: true,
      title: {
        text: "ĐỐI TƯỢNG KHÁCH HÀNG CỦA HỆ THỐNG",
        padding: "15",
        fontSize: 20,
        fontFamily: "tahoma",
        fontWeight: 700,
      },
      data: [{
        type: "pie",
        startAngle: 240,
        yValueFormatString: "##0.00\"%\"",
        indexLabel: "{label} {y}",
        dataPoints: [
          {y: (male/total)*100, label: "Nam"},
          {y: (female/total)*100, label: "Nữ"},
          {y: 100 - (female/total)*100 - (male/total)*100, label: "Đang cập nhật"}
        ]
      }]
    });
    var chart2 = new CanvasJS.Chart("chartContainerColumn", {
      animationEnabled: true,
      title:{
        text: "SO SÁNH NGƯỜI DÙNG CỦA HỆ THỐNG",
        padding: "15",
        fontSize: 20,
        fontFamily: "tahoma",
        fontWeight: 700,
      },
      axisY: {
        title: "Số người dùng",
        titleFontColor: "#4F81BC",
        lineColor: "#4F81BC",
        labelFontColor: "#4F81BC",
        tickColor: "#4F81BC"
      },
      toolTip: {
        shared: true
      },
      legend: {
        cursor:"pointer",
      },
      data: [{
        type: "column",
        name: "Tổng số người dùng",
        legendText: "Tổng số người dùng tại thời điểm",
        showInLegend: true,
        dataPoints:[
          { label: "Tháng 1", y: arrByMonth[0] },
          { label: "Tháng 2", y: arrByMonth[1] },
          { label: "Tháng 3", y: arrByMonth[2] },
          { label: "Tháng 4", y: arrByMonth[3] },
          { label: "Tháng 5", y: arrByMonth[4] },
          { label: "Tháng 6", y: arrByMonth[5] },
          { label: "Tháng 7", y: arrByMonth[6] },
          { label: "Tháng 8", y: arrByMonth[7] },
          { label: "Tháng 9", y: arrByMonth[8] },
          { label: "Tháng 10", y: arrByMonth[9] },
          { label: "Tháng 11", y: arrByMonth[10] },
          { label: "Tháng 12", y: arrByMonth[11] },
        ]
      },
        {
          type: "column",
          name: "Số người dùng mới trong tháng",
          legendText: "Số người mới trong tháng",
          showInLegend: true,
          dataPoints:[
            { label: "Tháng 1", y: arrEachMonth[0] },
            { label: "Tháng 2", y: arrEachMonth[1] },
            { label: "Tháng 3", y: arrEachMonth[2] },
            { label: "Tháng 4", y: arrEachMonth[3]},
            { label: "Tháng 5", y: arrEachMonth[4]},
            { label: "Tháng 6", y: arrEachMonth[5]},
            { label: "Tháng 7", y: arrEachMonth[6]},
            { label: "Tháng 8", y: arrEachMonth[7]},
            { label: "Tháng 9", y: arrEachMonth[8]},
            { label: "Tháng 10", y: arrEachMonth[9]},
            { label: "Tháng 11", y: arrEachMonth[10]},
            { label: "Tháng 12", y: arrEachMonth[11]},
          ]
        }]
    });
    var chart3 = new CanvasJS.Chart("chartContainerLine", {
      animationEnabled: true,
      theme: "light2",
      title:{
        text: "THỐNG KÊ NGƯỜI DÙNG MỚI",
        padding: "15",
        fontSize: 20,
        fontFamily: "tahoma",
        fontWeight: 700,
      },
      axisX:{
        crosshair: {
          enabled: true,
          snapToDataPoint: true
        }
      },
      axisY: {
        title: "Số người dùng",
        includeZero: true,
        crosshair: {
          enabled: true
        }
      },
      toolTip:{
        shared:true
      },
      legend:{
        cursor:"pointer",
        verticalAlign: "bottom",
        horizontalAlign: "left",
        dockInsidePlotArea: true,
      },
      data: [{
        type: "line",
        showInLegend: true,
        name: "Năm hiện tại",
        markerType: "square",
        color: "#F08080",
        dataPoints: [
          { x: 1, y: arrEachMonth[0] },
          { x: 2, y: arrEachMonth[1] },
          { x: 3, y: arrEachMonth[2] },
          { x: 4, y: arrEachMonth[3] },
          { x: 5, y: arrEachMonth[4] },
          { x: 6, y: arrEachMonth[5] },
          { x: 7, y: arrEachMonth[6] },
          { x: 8, y: arrEachMonth[7] },
          { x: 9, y: arrEachMonth[8] },
          { x: 10, y: arrEachMonth[9] },
          { x: 11, y: arrEachMonth[10] },
          { x: 12, y: arrEachMonth[11] },
        ]
      },
        {
          type: "line",
          showInLegend: true,
          name: "Năm trước",
          lineDashType: "dash",
          dataPoints: [
            { x: 1, y: arrEachMonthInLastYear[0]  },
            { x: 2, y: arrEachMonthInLastYear[1]  },
            { x: 3, y: arrEachMonthInLastYear[2]  },
            { x: 4, y: arrEachMonthInLastYear[3]  },
            { x: 5, y: arrEachMonthInLastYear[4]  },
            { x: 6, y: arrEachMonthInLastYear[5]  },
            { x: 7, y: arrEachMonthInLastYear[6]  },
            { x: 8, y: arrEachMonthInLastYear[7]  },
            { x: 9, y: arrEachMonthInLastYear[8]  },
            { x: 10, y: arrEachMonthInLastYear[9]  },
            { x: 11, y: arrEachMonthInLastYear[10]  },
            { x: 12, y: arrEachMonthInLastYear[11]  },
          ]
        }]
    });

    chart1.render();
    chart2.render();
    chart3.render();

  }
</script>
</body>
</html>
