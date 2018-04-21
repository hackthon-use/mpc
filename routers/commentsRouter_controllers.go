package routers

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context/param"
)

func init() {

	beego.GlobalControllerRouter["mpc/controllers:KycController"] = append(beego.GlobalControllerRouter["mpc/controllers:KycController"],
		beego.ControllerComments{
			Method: "Compute",
			Router: `/compute`,
			AllowHTTPMethods: []string{"post"},
			MethodParams: param.Make(),
			Params: nil})

}
