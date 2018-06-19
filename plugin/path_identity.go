package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	SecretTypeIdentity = "identity"
	uaiPath            = "uai"
)

type identityAssignments map[string][]string

func secretIdentity(b *azureSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretTypeIdentity,
		Revoke: b.identityRevoke,
	}
}

func pathIdentity(b *azureSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("identity/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the identity role.",
			},
			"resource_group": {
				Type:        framework.TypeString,
				Description: "Resource group of the requesting VM.",
			},
			"vm_name": {
				Type:        framework.TypeString,
				Description: "Name of the requesting VM.",
			},
			"jwt": {
				Type:        framework.TypeString,
				Description: "Metadata JWT from the requesting VM.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathIdentity,
			logical.CreateOperation: b.pathIdentity,
			logical.UpdateOperation: b.pathIdentity,
		},
		//HelpSynopsis:    pathTokenHelpSyn,
		//HelpDescription: pathTokenHelpDesc,
	}
}

func (b *azureSecretBackend) pathIdentity(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// verify input parameters
	vmName := d.Get("vm_name").(string)
	if vmName == "" {
		return logical.ErrorResponse("vm_name missing"), nil
	}

	resourceGroup := d.Get("resource_group").(string)
	if resourceGroup == "" {
		return logical.ErrorResponse("resource_group missing"), nil
	}

	signedJwt := d.Get("jwt").(string)
	if signedJwt == "" {
		return logical.ErrorResponse("jwt missing"), nil
	}

	roleName := d.Get("role").(string)
	role, err := getRole(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exists", roleName)), nil
	}

	// load and verify role
	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("error during identity create: could not load config")
	}

	if role.CredentialType != SecretTypeIdentity {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' is not an identity role", roleName)), nil
	}

	// verify JWT and requested target VM
	c, err := b.newAzureClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	principalID, err := c.verifyToken(ctx, signedJwt)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	vm, err := c.provider.VMGet(ctx, resourceGroup, vmName, "")
	if err != nil {
		return nil, err
	}

	if *vm.Identity.PrincipalID != principalID {
		return logical.ErrorResponse("token object id does not match virtual machine principal id"), nil
	}

	// update and store identity assignment
	lock := locksutil.LockForKey(b.identityLocks, principalID)
	lock.Lock()
	defer lock.Unlock()

	identities, err := loadIdentityAssignment(ctx, principalID, req.Storage)
	if err != nil {
		return nil, err
	}

	assignmentID, err := identities.add(role.ResourceGroup, role.Identity)
	if err != nil {
		return nil, err
	}

	if err := c.updateMachineIdentities(ctx, resourceGroup, vmName, identities.slice()); err != nil {
		return nil, err
	}

	if err := storeIdentityAssignment(ctx, principalID, identities, req.Storage); err != nil {
		return nil, err
	}

	resp := b.Secret(SecretTypeIdentity).Response(map[string]interface{}{},
		map[string]interface{}{
			"assignmentID":  assignmentID,
			"principalID":   principalID,
			"vmName":        vmName,
			"resourceGroup": resourceGroup,
		})

	if role.DefaultTTL > 0 {
		resp.Secret.TTL = role.DefaultTTL
	} else {
		resp.Secret.TTL = cfg.DefaultTTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	} else {
		resp.Secret.MaxTTL = cfg.MaxTTL
	}

	return resp, nil
}

func (b *azureSecretBackend) identityRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	principalID, err := GetInternalString(req, "principalID")
	if err != nil {
		return nil, err
	}

	assignmentID, err := GetInternalString(req, "assignmentID")
	if err != nil {
		return nil, err
	}

	vmName, err := GetInternalString(req, "vmName")
	if err != nil {
		return nil, err
	}

	resourceGroup, err := GetInternalString(req, "resourceGroup")
	if err != nil {
		return nil, err
	}

	cfg, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("error during identity create: could not load config")
	}

	c, err := b.newAzureClient(ctx, cfg)
	if err != nil {
		return nil, err
	}

	lock := locksutil.LockForKey(b.identityLocks, principalID)
	lock.Lock()
	defer lock.Unlock()

	identities, err := loadIdentityAssignment(ctx, principalID, req.Storage)
	if err != nil {
		return nil, err
	}
	identities.remove(assignmentID)

	if err := c.updateMachineIdentities(ctx, resourceGroup, vmName, identities.slice()); err != nil {
		return nil, err
	}

	if err := storeIdentityAssignment(ctx, principalID, identities, req.Storage); err != nil {
		return nil, err
	}

	return nil, nil
}

type identityAssignment struct {
	Assignments map[string]assignment `json:"assignments"`
}

func (i *identityAssignment) add(resourceGroup, identity string) (string, error) {
	uuid, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}

	i.Assignments[uuid] = assignment{
		ResourceGroup: resourceGroup,
		IdentityName:  identity,
	}

	return uuid, nil
}

func (i *identityAssignment) remove(assignmentID string) {
	delete(i.Assignments, assignmentID)
}

func (i *identityAssignment) slice() []assignment {
	var identitySet []assignment

	set := make(map[assignment]bool)
	for _, v := range i.Assignments {
		if !set[v] {
			identitySet = append(identitySet, v)
			set[v] = true
		}
	}
	sort.Slice(identitySet, func(i, j int) bool {
		a, b := identitySet[i], identitySet[j]
		if a.ResourceGroup == b.ResourceGroup {
			return a.IdentityName < b.IdentityName
		}
		return a.ResourceGroup < b.ResourceGroup
	})

	return identitySet
}

type assignment struct {
	ResourceGroup string `json:"resource_group"`
	IdentityName  string `json:"identity"`
}

func loadIdentityAssignment(ctx context.Context, principalID string, s logical.Storage) (*identityAssignment, error) {
	key := path.Join(uaiPath, principalID)
	entry, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var data identityAssignment
	if entry != nil {
		if err := entry.DecodeJSON(&data); err != nil {
			return nil, err
		}
	} else {
		data.Assignments = make(map[string]assignment)
	}

	return &data, nil
}

func storeIdentityAssignment(ctx context.Context, principalID string, is *identityAssignment, s logical.Storage) error {
	key := path.Join(uaiPath, principalID)

	b, err := jsonutil.EncodeJSON(is)
	if err != nil {
		return err
	}

	entry := &logical.StorageEntry{
		Key:   key,
		Value: b,
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

func deleteIdentityAssignment(ctx context.Context, principalID string, assignmentID string, s logical.Storage) ([]assignment, error) {
	data, err := loadIdentityAssignment(ctx, principalID, s)
	if err != nil {
		return nil, err
	}

	data.remove(assignmentID)

	if err = storeIdentityAssignment(ctx, principalID, data, s); err != nil {
		return nil, err
	}

	return data.slice(), nil
}
