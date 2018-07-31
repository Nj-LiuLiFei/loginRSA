<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html lang="CN">
<head>
    <script src="https://cdn.bootcss.com/jquery/1.11.0/jquery.min.js"></script>
    <script src="js/jsencrypt.min.js"></script>
</head>
<body>
<h2>登录RSA公钥加密</h2>
<%
  String pubKey = (String) request.getServletContext().getAttribute("pubKey");
%>
<form id="loginForm" action="/user/login" method="post" onsubmit="return false;">
    <input id="password" type="password" placeholder="请输入密码" name="password">
    <input id="pubKey" type="hidden" name="pubKey" value="${pubKey}">
    <button id="loginSubmitBtn" type="submit">登录</button>
</form>
<script>
    $(function () {
        $("#loginSubmitBtn").on("click",function () {
            $(this).attr("disabled","disabled");
            $(this).attr("value","加密中");
            // Encrypt with the public key...
            var encrypt = new JSEncrypt();
            encrypt.setPublicKey($('#pubKey').val());
            var encrypted = encrypt.encrypt($('#password').val());
            $('#password').val(encrypted);
            $("#loginForm").attr("onsubmit","");
            $("#loginForm").submit();
            //$(this).removeAttr("disabled");
        });
    });
</script>
</body>
</html>
