package sops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	scommon "go.mozilla.org/sops/v3/cmd/sops/common"
)

func GetInputStore(d *schema.ResourceData) scommon.Store {
	return scommon.DefaultStoreForPathOrFormat(d.Get("filename").(string), "file")
}
func GetOutputStore(d *schema.ResourceData) scommon.Store {
	return scommon.DefaultStoreForPathOrFormat(d.Get("filename").(string), "file")
}
