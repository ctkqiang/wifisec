package model

import "fmt"

type Developer struct {
	Id           *int   `json:"id"`
	Name         string `json:"name"`
	Organisation string `json:"organisation"`
	Email        string `json:"email"`
	Weixin       string `json:"weixin"`
	Version      string `json:"version"`
	ProjectUrl   string `json:"projectUrl"`
}

func (d *Developer) String() string {
	return fmt.Sprintf(
		"开发者信息\n"+
			"--------------------\n"+
			"  姓名         : %s\n"+
			"  组织         : %s\n"+
			"  邮箱         : %s\n"+
			"  微信         : %s\n"+
			"  版本         : %s\n"+
			"  项目URL      : %s",
		d.Name,
		d.Organisation,
		d.Email,
		d.Weixin,
		d.Version,
		d.ProjectUrl,
	)
}
