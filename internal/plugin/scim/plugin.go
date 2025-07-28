package scim

import (
	"context"
	"errors"

	"github.com/hashicorp/go-hclog"
	"github.com/samber/oops"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/utils/errs"
	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"
	configv1 "github.com/openkcm/plugin-sdk/proto/service/common/config/v1"
)

var (
	ErrPluginCreation   = errors.New("failed to create plugin")
	ErrGetGroupsForUser = errors.New("failed to get groups for user")
	ErrGetUsersForGroup = errors.New("failed to get users for group")
)

const defaultFilterAttribute = "displayName"
const defaultUsersFilterAttribute = defaultFilterAttribute
const defaultGroupsFilterAttribute = defaultFilterAttribute

// Plugin is a simple test implementation of KeystoreProviderServer
type Plugin struct {
	idmangv1.UnsafeIdentityManagementServiceServer
	configv1.UnsafeConfigServer
	logger        hclog.Logger
	scimClient    *scim.APIClient
	requestParams RequestParams
}

type RequestParams struct {
	GroupAttribute *string `yaml:"groupattribute"`
	UserAttribute  *string `yaml:"userattribute"`
}

type Config struct {
	ConnectCfg    scim.APIParams `yaml:"connectcfg"`
	RequestParams RequestParams  `yaml:"requestparams"`
}

var (
	_ idmangv1.IdentityManagementServiceServer = (*Plugin)(nil)
	_ configv1.ConfigServer                    = (*Plugin)(nil)
)

func NewPlugin() *Plugin {
	return &Plugin{}
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) Configure(
	ctx context.Context,
	req *configv1.ConfigureRequest,
) (*configv1.ConfigureResponse, error) {
	p.logger.Info("Configuring plugin")

	var cfg Config

	err := yaml.Unmarshal([]byte(req.GetYamlConfiguration()), &cfg)
	if err != nil {
		return nil, oops.In("Identity management Plugin").
			Wrapf(err, "Failed to get yaml Configuration")
	}

	client, err := scim.NewClient(ctx, cfg.ConnectCfg)
	if err != nil {
		return nil, err
	}

	p.scimClient = client

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) GetUsersForGroup(
	ctx context.Context,
	request *idmangv1.GetUsersForGroupRequest,
) (*idmangv1.GetUsersForGroupResponse, error) {
	filter := getFilter(defaultGroupsFilterAttribute, request.GroupId,
		p.requestParams.GroupAttribute)
	users, err := p.scimClient.ListUsers(ctx, true, filter, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetUsersForGroup, err)
	}
	responseUsers := make([]*idmangv1.User, len(users.Resources))
	for i, user := range users.Resources {
		responseUsers[i] = &idmangv1.User{Name: user.DisplayName}
	}
	return &idmangv1.GetUsersForGroupResponse{Users: responseUsers}, nil
}

func (p *Plugin) GetGroupsForUser(
	ctx context.Context,
	request *idmangv1.GetGroupsForUserRequest,
) (*idmangv1.GetGroupsForUserResponse, error) {
	filter := getFilter(defaultUsersFilterAttribute, request.UserId,
		p.requestParams.UserAttribute)
	groups, err := p.scimClient.ListGroups(ctx, true, filter, nil, nil)
	if err != nil {
		return nil, errs.Wrap(ErrGetGroupsForUser, err)
	}
	responseGroups := make([]*idmangv1.Group, len(groups.Resources))
	for i, group := range groups.Resources {
		responseGroups[i] = &idmangv1.Group{Name: group.DisplayName}
	}

	return &idmangv1.GetGroupsForUserResponse{Groups: responseGroups}, nil
}

func getFilter(defaultAttribute, value string, setAttribute *string) scim.FilterComparison {
	filter := scim.FilterComparison{
		Attribute: defaultAttribute,
		Operator:  scim.FilterOperatorEqual,
		Value:     value,
	}
	if setAttribute != nil {
		filter.Attribute = *setAttribute
	}
	return filter
}
