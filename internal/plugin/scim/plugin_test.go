package scim_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/magodo/slog2hclog"
	"github.com/stretchr/testify/assert"

	idmangv1 "github.com/openkcm/plugin-sdk/proto/plugin/identity_management/v1"

	plugin "github.com/openkcm/identity-management-plugins/cmd/scim"
	"github.com/openkcm/identity-management-plugins/pkg/clients/scim"
	"github.com/openkcm/identity-management-plugins/pkg/utils/ptr"
)

const (
	NonExistentField = "Non-existent"
	GetUserResponse  = `{"id":"d1a6888d-7fd5-4c3f-ae33-177b24aae627",` +
		`"meta":{"created":"2020-04-10T11:29:36Z","lastModified":"2021-05-18T15:18:00Z",` +
		`"location":"https://a2e15w1y0.accounts400.ondemand.com/scim/Users/d1a6888d-7fd5-4c3f-ae33-177b24aae627",` +
		`"resourceType":"User", "groups.cnt":0}, "schemas":["urn:ietf:params:scim:schemas:core:2.0:User",` +
		`"urn:ietf:params:scim:schemas:extension:sap:2.0:User"], "userName":"cloudanalyst",` +
		`"name":{"familyName":"Analyst", "givenName":"Cloud"}, "displayName":"None", "userType":"employee",` +
		`"active":true, "emails":[{"value":"cloud.analyst@example.com", "primary":true}],` +
		`"groups":[{"value":"d1a6888d-7fd5-4c3f-ae33-177b24aae627", "display":"CloudAnalyst"}],` +
		`"urn:ietf:params:scim:schemas:extension:sap:2.0:User":` +
		`{"emails":[{"verified":false, "value":"cloud.analyst@example.com", "primary":true}],` +
		`"sourceSystem":0, "userUuid":"d1a6888d-7fd5-4c3f-ae33-177b24aae627",` +
		`"mailVerified":false, "userId":"P000011", "status":"active",` +
		`"passwordDetails":{"failedLoginAttempts":0, "setTime":"2020-04-10T11:29:36Z",` +
		`"status":"initial", "policy":"https://accounts.sap.com/policy/passwords/sap/web/1.1"}}}`
	ListUsersResponse = `{"Resources":[` + GetUserResponse + `],` +
		`"totalResults":1, "startIndex": 1, "itemsPerPage":1,` +
		`"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`

	GetGroupResponse = `{"id":"16e720aa-a009-4949-9bf9-847fb0660522",` +
		`"meta":{"created":"2020-11-12T14:55:12Z","lastModified":"2021-03-31T14:56:01Z",` +
		`"location":"https://a2e15w1y0.accounts400.ondemand.com/scim/Groups/16e720aa-a009-4949-9bf9-847fb0660522",` +
		`"version":"f5c7bafe-b86f-4741-a35a-b53fe07b25e6","resourceType":"Group"},` +
		`"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group",` +
		`"urn:sap:cloud:scim:schemas:extension:custom:2.0:Group"],"displayName":"KeyAdmin",` +
		`"members":[{"value":"700223c4-3b58-4358-8594-59d14e619f4a","type":"User"}],` +
		`"urn:sap:cloud:scim:schemas:extension:custom:2.0:Group":{"name":"KeyAdmin",` +
		`"additionalId":"5f079f17cbf5f51d531d28f7","description":""}}`
	ListGroupsResponse = `{"Resources":[` + GetGroupResponse + `],` +
		`"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],` +
		`"totalResults":1,"itemsPerPage":1,"startIndex":1}`
	EmptyResponse = `{"Resources":[],` +
		`"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],` +
		`"totalResults":0,"itemsPerPage":1,"startIndex":0}`
)

var NonExistentFieldPtr *string = ptr.PointTo(NonExistentField)

func setupTest(t *testing.T, url string,
	groupFilterAttribute, userFilterAttribute *string) *plugin.Plugin {
	p, err := plugin.NewPlugin(
		plugin.Config{
			ConnectCfg: scim.APIParams{
				Host:         url,
				ClientID:     "test-client",
				ClientSecret: "unreal",
			},
			RequestParams: plugin.RequestParams{
				GroupFilterAttribute: groupFilterAttribute,
				UserFilterAttribute:  userFilterAttribute,
			},
		})
	assert.NotNil(t, p)
	assert.NoError(t, err)

	logLevelPlugin := new(slog.LevelVar)
	logLevelPlugin.Set(slog.LevelError)

	p.SetLogger(slog2hclog.New(slog.Default(), logLevelPlugin))
	return p
}

func TestGetUsersForGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		// Quick and dirty mock server filtering. Fine since we aren't testing server here
		reqStr := string(bodyBytes)
		if strings.Contains(reqStr, NonExistentField) {
			_, err = w.Write([]byte(EmptyResponse))
		} else {
			_, err = w.Write([]byte(ListUsersResponse))
		}
		assert.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name                 string
		serverUrl            string
		groupFilterAttribute *string
		groupFilterValue     *string
		testNumUsers         int
		testUserName         string
		testExpectedError    *error
	}{
		{
			name:                 "Bad Server",
			serverUrl:            "badurl",
			groupFilterAttribute: nil,
			groupFilterValue:     nil,
			testNumUsers:         0,
			testUserName:         "",
			testExpectedError:    &scim.ErrListUsers,
		},
		{
			name:                 "No filters",
			serverUrl:            server.URL,
			groupFilterAttribute: nil,
			groupFilterValue:     nil,
			testNumUsers:         1,
			testUserName:         "None",
			testExpectedError:    nil,
		},
		{
			name:                 "Non-existent filter value",
			serverUrl:            server.URL,
			groupFilterAttribute: ptr.PointTo("displayName"),
			groupFilterValue:     NonExistentFieldPtr,
			testNumUsers:         0,
			testUserName:         "",
			testExpectedError:    nil,
		},
		{
			name:                 "Non-existent filter attribute",
			serverUrl:            server.URL,
			groupFilterAttribute: NonExistentFieldPtr,
			groupFilterValue:     ptr.PointTo("None"),
			testNumUsers:         0,
			testUserName:         "",
			testExpectedError:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			p := setupTest(t, tt.serverUrl, tt.groupFilterAttribute, nil)
			var groupFilterValue = idmangv1.GetUsersForGroupRequest{}
			if tt.groupFilterValue != nil {
				groupFilterValue.GroupId = *tt.groupFilterValue
			}
			responseMsg, err := p.GetUsersForGroup(context.Background(),
				&groupFilterValue)

			if tt.testExpectedError == nil {
				assert.NoError(t, err)
				assert.Equal(t, tt.testNumUsers, len(responseMsg.Users))
				if tt.testNumUsers > 0 {
					assert.Equal(
						t,
						&idmangv1.GetUsersForGroupResponse{
							Users: []*idmangv1.User{
								&idmangv1.User{Name: tt.testUserName},
							},
						},
						responseMsg,
					)
				}
			} else {
				assert.ErrorIs(t, err, *tt.testExpectedError)
			}
		})
	}
}

func TestGetGroupsForUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		// Quick and dirty mock server filtering. Fine since we aren't testing server here
		reqStr := string(bodyBytes)
		if strings.Contains(reqStr, NonExistentField) {
			_, err = w.Write([]byte(EmptyResponse))
		} else {
			_, err = w.Write([]byte(ListGroupsResponse))
		}
		assert.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name                string
		serverUrl           string
		userFilterAttribute *string
		userFilterValue     *string
		testNumGroups       int
		testGroupName       string
		testExpectedError   *error
	}{
		{
			name:                "Bad Server",
			serverUrl:           "badurl",
			userFilterAttribute: nil,
			userFilterValue:     nil,
			testNumGroups:       0,
			testGroupName:       "",
			testExpectedError:   &scim.ErrListGroups,
		},
		{
			name:                "No filters",
			serverUrl:           server.URL,
			userFilterAttribute: nil,
			userFilterValue:     nil,
			testNumGroups:       1,
			testGroupName:       "KeyAdmin",
			testExpectedError:   nil,
		},
		{
			name:                "Non-existent filter value",
			serverUrl:           server.URL,
			userFilterAttribute: ptr.PointTo("displayName"),
			userFilterValue:     NonExistentFieldPtr,
			testNumGroups:       0,
			testGroupName:       "",
			testExpectedError:   nil,
		},
		{
			name:                "Non-existent filter attribute",
			serverUrl:           server.URL,
			userFilterAttribute: NonExistentFieldPtr,
			userFilterValue:     ptr.PointTo("None"),
			testNumGroups:       0,
			testGroupName:       "",
			testExpectedError:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := setupTest(t, tt.serverUrl, nil, tt.userFilterAttribute)

			var userFilterValue = idmangv1.GetGroupsForUserRequest{}
			if tt.userFilterValue != nil {
				userFilterValue.UserId = *tt.userFilterValue
			}
			responseMsg, err := p.GetGroupsForUser(context.Background(),
				&userFilterValue)

			if tt.testExpectedError == nil {
				assert.NoError(t, err)
				assert.Equal(t, tt.testNumGroups, len(responseMsg.Groups))
				if tt.testNumGroups > 0 {
					assert.Equal(
						t,
						&idmangv1.GetGroupsForUserResponse{
							Groups: []*idmangv1.Group{
								&idmangv1.Group{Name: tt.testGroupName},
							},
						},
						responseMsg,
					)
				}
			} else {
				assert.ErrorIs(t, err, *tt.testExpectedError)
			}
		})
	}
}

func TestNewPlugin(t *testing.T) {
	p := setupTest(t, "", nil, nil)
	assert.NotNil(t, p)
}
