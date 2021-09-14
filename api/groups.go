package api

import (
	"context"
)

type GroupsClient interface {
	AddGroupMember(ctx context.Context, groupObjectID string, memberObjectID string) error
	RemoveGroupMember(ctx context.Context, groupObjectID, memberObjectID string) error
	GetGroup(ctx context.Context, objectID string) (result ADGroup, err error)
	ListGroups(ctx context.Context, filter string) (result []ADGroup, err error)
}

type ADGroup struct {
	ID          string
	DisplayName string
}
