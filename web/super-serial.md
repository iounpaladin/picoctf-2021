# Introduction
## Problem Details

Category: Web Exploitation
Points: 130
#### Description

Try to recover the flag stored on this website  [http://mercury.picoctf.net:14804/](http://mercury.picoctf.net:14804/)

## Writeup
This challenge has a (somewhat annoying) gimmick that makes it difficult to start. Going to [http://mercury.picoctf.net:14804/index.phps](http://mercury.picoctf.net:14804/index.phps) shows the source code for the main page. We see a `cookie.php` requirement and a `authentication.php` redirect. Looking at all of these sources, we see a vulnerability in `cookie.php`:
```js
if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}
```

This unserialize is unsafe. Notice that if the unserialize fails (*or* the `$perm->is_guest()` fails), then the `$perm` object is outputted. In `authentication.php`, there is an interesting class that does something useful on `__toString()`:
```js
class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}
```

Simply edit the cookie to a serialized, base64 and URL encoded access_log pointing to `../flag` and request the main page. The error message contains the flag.