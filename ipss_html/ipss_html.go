// ipss_html provides HTML templates for the IP Self Serve web interface.
package ipss_html

import "html"

// HTMLroot returns the login form. extraFields is injected HTML for second-factor inputs.
// csrfToken is embedded as a hidden form field for CSRF protection.
// ip is the detected client IP displayed above the form.
// defaultIP is "connection" or "external", controlling which radio button is pre-selected
// when the external IP differs from the connection IP.
func HTMLroot(extraFields, csrfToken, ip, defaultIP string) string {
	return `<!DOCTYPE html>
<html>
<head>
<style>
label{
width: 6em;
float: left;
text-align: right;
margin-right: 0.5em;
display: block
}
#ip-choice { margin: 0.5em 0; }
#ip-choice label { width: auto; float: none; text-align: left; }
</style>
</head>
<body>
<h2>IP Self Service</h2>
<p id="ip-display">Your detected IP: ` + html.EscapeString(ip) + `</p>
<div id="ip-choice" style="display:none"></div>
<form action="/validate" method="post">
<input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `" />
<input type="hidden" name="selected_ip" id="selected-ip" value="` + html.EscapeString(ip) + `" />
<label for="username">Username:</label><input type="text" name="username" /><br/>
<label for="password">Password:</label><input type="password" name="password" /><br/>
` + extraFields + `
<label for="comment">Comment:</label><input type="text" name="comment" /><br/>
<br class="clear" />
<br />
<input type="submit" value="Submit" />
</form>
<script>
(function(){
var connectionIP = "` + html.EscapeString(ip) + `";
var defaultIP = "` + html.EscapeString(defaultIP) + `";
fetch("https://api.ipify.org").then(function(r){ return r.text(); }).then(function(extIP){
	extIP = extIP.trim();
	if (!extIP || extIP === connectionIP) return;
	var preselect = (defaultIP === "external") ? extIP : connectionIP;
	document.getElementById("selected-ip").value = preselect;
	document.getElementById("ip-display").style.display = "none";
	var div = document.getElementById("ip-choice");
	div.style.display = "";
	div.innerHTML =
		'<p>Two IPs detected — choose which to submit:</p>' +
		'<label><input type="radio" name="ip_radio" value="' + connectionIP + '"' +
			(preselect === connectionIP ? ' checked' : '') +
			'> Connection IP: ' + connectionIP + '</label><br>' +
		'<label><input type="radio" name="ip_radio" value="' + extIP + '"' +
			(preselect === extIP ? ' checked' : '') +
			'> External IP: ' + extIP + '</label>';
	var radios = div.querySelectorAll('input[name="ip_radio"]');
	for (var i = 0; i < radios.length; i++) {
		radios[i].addEventListener("change", function(){
			document.getElementById("selected-ip").value = this.value;
		});
	}
}).catch(function(){});
})();
</script>
</body>
</html>`
}

func HTMLvalidated() string {
	return `<!DOCTYPE html>
<html>
<body>
<p>IP successfully captured.</p>
</body>
</html>`
}

func HTMLinvalidComment() string {
	return `<!DOCTYPE html>
<html>
<body>
<p>Commas are not allowed in the comment field.</p>
<a href="/">Try again</a>
</body>
</html>`
}

func HTMLfailed() string {
	return `<!DOCTYPE html>
<html>
<body>
<p>Authentication failed.</p>
<a href="/">Try again</a>
</body>
</html>`
}
