package ipss_html

func HTMLroot() string {
	return `
<style>
label{
width: 6em;
float: left;
text-align: right;
margin-right: 0.5em;
display: block
}
</style>
<!DOCTYPE html>
<html>
<body>
<h2>IP Self Service</h2>
<form action="/validate" method=post>
<label for="username">Username:</label>                   <input type="text" 		name="username" /><br/>
<label for="password">Password: </label>                  <input type="password" 	name="password" /><br/>
<label for="trivial_password">Dynamic Password: </label>  <input type="password"	name="dynamic_password" /><br/>
<br class="clear" />
<br />
<input type="submit" value="submit" />
<input type="button" class="floatright" value="Cancel"  /><br class="clear"/>
</form>
</body>
</html> 
`
}

func HTMLvalidated() string {
	return `
<!DOCTYPE html>
<html>
<body>

IP succesfully captured<b>


</body>
</html> 
`
}

func HTMLfailed() string {
	return `
<!DOCTYPE html>
<html>
<body>

Incorrect user or password<p>
<a href="/">Try again</a>

</body>
</html> 
`
}

func HTMLfailed_dynamic() string {
	return `
<!DOCTYPE html>
<html>
<body>

Invalid dynamic password<p>
<a href="/">Try again</a>

</body>
</html> 
`
}
