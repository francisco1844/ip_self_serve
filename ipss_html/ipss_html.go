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

<h2>IP Self Service</h2>
<form action="/validate" method=post>
<label for="username">Username:</label>                   <input type="text" name="username" /><br/>
<label for="password">Password: </label>                  <input type="text" name="password" /><br/>
<label for="trivial_password">Trivial Password: </label>  <input type="text" name="trivial_password" /><br/>
<br class="clear" />
<br />
<input type="submit" value="submit" />
<input type="button" class="floatright" value="Cancel"  /><br class="clear"/>
</form>
`
}