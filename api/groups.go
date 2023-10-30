// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type GroupsClient interface {
	AddGroupMember(ctx context.Context, groupObjectID string, memberObjectID string) error
	RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) error
	GetGroup(ctx context.Context, objectID string) (result models.Groupable, err error)
	ListGroups(ctx context.Context, filter string) (result []models.Groupable, err error)
}

type Group struct {
	ID          string
	DisplayName string
}

func (c *AppClient) AddGroupMember(ctx context.Context, groupObjectID string, memberObjectID string) error {
	req := models.NewReferenceCreate()
	odataId := "https://graph.microsoft.com/v1.0/directoryObjects/{id}"
	req.SetOdataId(&odataId)

	return c.client.Groups().ByGroupId(groupObjectID).Members().Ref().Post(ctx, req, nil)
}

func (c *AppClient) RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) error {
	return c.client.Groups().ByGroupId(groupObjectID).Members().ByDirectoryObjectId(memberObjectID).Ref().Delete(ctx, nil)
}

func (c *AppClient) GetGroup(ctx context.Context, groupID string) (models.Groupable, error) {
	return c.client.Groups().ByGroupId(groupID).Get(ctx, nil)
}

func (c *AppClient) ListGroups(ctx context.Context, filter string) ([]models.Groupable, error) {
	headers := abstractions.NewRequestHeaders()
	headers.Add("ConsistencyLevel", "eventual")

	req := &groups.GroupsRequestBuilderGetQueryParameters{
		Filter: &filter,
	}
	configuration := &groups.GroupsRequestBuilderGetRequestConfiguration{
		Headers:         headers,
		QueryParameters: req,
	}

	groupList, err := c.client.Groups().Get(ctx, configuration)
	if err != nil {
		return nil, err
	}

	return groupList.GetValue(), nil
}
