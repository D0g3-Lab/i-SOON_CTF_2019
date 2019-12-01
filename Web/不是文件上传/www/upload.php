<!DOCTYPE html>
<html>
<head>
	<title>Image Upload</title>
	<link rel="stylesheet" href="./style.css">
	<meta http-equiv="content-type" content="text/html;charset=UTF-8"/>
</head>
<body>
<p align="center"><img src="https://i.loli.net/2019/10/06/i5GVSYnB1mZRaFj.png" width=300 length=150></p>
<div align="center">
<form name="upload" action=""  method="post" enctype ="multipart/form-data" >
    <input type="file" name="file">
    <input type="Submit" value="submit">
</form>
</div>

<br> 
<p><a href="./show.php">You can view the pictures you uploaded here</a></p>
<br>

<?php
include("./helper.php");
class upload extends helper {
	public function upload_base(){
		$this->upload();
	}
}

if ($_FILES){
	if ($_FILES["file"]["error"]){
		die("Upload file failed.");
	}else{
		$file = new upload();
		$file->upload_base();
	}
}

$a = new helper();
?>
</body>
</html>