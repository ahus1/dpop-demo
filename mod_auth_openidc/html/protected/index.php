<html>
<body>

<h1>Hello, <?php echo($_SERVER['REMOTE_USER']) ?></h1>

<a href="/protected/redirect_uri?logout=http%3A%2F%2Flocalhost:8000%2Floggedout.html">Logout</a>

<pre><?php print_r(array_map("htmlentities", apache_request_headers())); ?></pre>
</body>
</html>