package main

import (
	"github.com/openkcm/plugin-sdk/pkg/plugin"

	"github.com/openkcm/identity-management-plugins/internal/plugin/scim"
	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"
)

func main() {
	p := scim.NewPlugin()

	plugin.Serve(
		idmangv1.IdentityManagementServicePluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
