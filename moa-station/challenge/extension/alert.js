const url = new URL(window.location.href);
const offensiveText = url.searchParams.get('offensive_text');
const alert_html = `M.O.A. CITATION
<hr />
Protocol Violated.<br />
Forbidden words used: <br />
... ${offensiveText} ...
<hr />
<center>WARNING - NO PENALTY</center>`;

$(".citation").html(alert_html);
