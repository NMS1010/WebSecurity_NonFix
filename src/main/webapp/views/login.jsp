
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@include file="/common/taglib.jsp" %>
<c:url value="/LoginGoogleHandler" var="URL"/>
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
<section class="sign-in-page">

    <div class="container p-0">
        <div class="row no-gutters height-self-center">
            <div class="col-sm-12 align-self-center page-content rounded">
                <div class="row m-0">
                    <div class="col-sm-12 sign-in-page-data">
                        <div class="sign-in-from" style="padding: 0">
                            <%@include file="/common/info.jsp"%>
                        </div>
                        <div class="sign-in-from bg-primary rounded">

                            <h3 class="mb-0 text-center text-white">Đăng nhập</h3>
                            <form action="login" method="post" class="mt-4 form-text">
                                <div class="form-group">
                                    <label>Địa chỉ email</label>
                                    <input type="email" class="form-control mb-0 bg-light text-black" name="username"
                                           placeholder="Nhập email">
                                </div>
                                <div class="form-group">
                                    <label>Password</label>
                                    <input type="password" class="form-control mb-0 bg-light text-black" name="password"
                                           placeholder="Nhập password">
                                </div>
                                <div class="sign-info text-center">
                                    <button type="submit" class="btn btn-white d-block w-100 mb-2">Đăng nhập</button>
                                    <span class="text-dark dark-color d-inline-block line-height-2">Bạn chưa có tài
                                        khoản ? <a href="<c:url value="/signup"/>" class="text-white">Đăng ký</a></span>
                                </div>
                            </form>
                            <div class="d-flex justify-content-center">
                                <a class="btn btn-danger"
                                   href="https://accounts.google.com/o/oauth2/auth?scope=email%20profile%20openid&redirect_uri=http://localhost:8080${URL}&response_type=code&client_id=740094574805-pa2bc895e0nmd2h00b6njulev52331qg.apps.googleusercontent.com&approval_prompt=force">
                                    <i class="fa-brands fa-google"></i>
                                    Tiếp tục với Google
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>
</body>
</html>
