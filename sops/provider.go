package sops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{},
		DataSourcesMap: map[string]*schema.Resource{
			"sops_file":     dataSourceFile(),
			"sops_external": dataSourceExternal(),
		},
		ResourcesMap: map[string]*schema.Resource{
			"sops_file": resourceSourceFile(),
		},
	}
}
