// ipss_html provides HTML templates for the IP Self Serve web interface.
package ipss_html

import "html"

// HTMLroot returns the login form. extraFields is injected HTML for second-factor inputs.
// csrfToken is embedded as a hidden form field for CSRF protection.
func HTMLroot(extraFields, csrfToken string) string {
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
</style>
</head>
<body>
<h2>IP Self Service</h2>
<form action="/validate" method="post">
<input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `" />
<label for="username">Username:</label><input type="text" name="username" /><br/>
<label for="password">Password:</label><input type="password" name="password" /><br/>
` + extraFields + `
<br class="clear" />
<br />
<input type="submit" value="Submit" />
</form>
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

func HTMLfailed() string {
	return `<!DOCTYPE html>
<html>
<body>
<p>Authentication failed.</p>
<a href="/">Try again</a>
</body>
</html>`
}
