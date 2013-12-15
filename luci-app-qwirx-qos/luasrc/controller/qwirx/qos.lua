module("luci.controller.qwirx.qos", package.seeall)

function index()
	local e
	e = entry({"click", "here", "now"}, call("action_tryme"), "Click here", 10)

	e = entry({"my", "new", "template"}, template("qwirx-qos/example"), "Hello world", 20)
	e.dependent = false
	e.index = true

	e = entry({"mini", "network", "qos"}, template("qwirx-qos/example"), "Quality of Service", 20)
	e.dependent = false
	e.index = true

	entry({"rpc", "qos"}, call("rpc_qos"))
end
 
function action_tryme()
	luci.http.prepare_content("text/plain")
	luci.http.write("Haha, rebooting now...")
	luci.sys.reboot()
end
