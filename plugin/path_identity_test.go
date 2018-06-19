package azuresecrets

import (
	"context"
	"testing"
)

func TestStoreIdentityAssignment(t *testing.T) {
	_, s := getTestBackend(t, true)

	const ADD = 1
	const DEL = 2
	tests := []*struct {
		step                        int
		op                          int
		vm, resourceGroup, identity string
		deleteIndex                 int
		assignedID                  string
		identitySet                 []assignment
	}{
		{0, ADD, "vm1", "rg1", "i1", -1, "", []assignment{{"rg1", "i1"}}},
		{1, ADD, "vm1", "rg2", "i2", -1, "", []assignment{{"rg1", "i1"}, {"rg2", "i2"}}},
		{2, ADD, "vm1", "rg1", "i1", -1, "", []assignment{{"rg1", "i1"}, {"rg2", "i2"}}},
		{3, ADD, "vm1", "rg1", "i2", -1, "", []assignment{{"rg1", "i1"}, {"rg1", "i2"}, {"rg2", "i2"}}},
		{4, ADD, "vm2", "rg3", "i3", -1, "", []assignment{{"rg3", "i3"}}},
		{5, DEL, "vm1", "", "", 3, "", []assignment{{"rg1", "i1"}, {"rg2", "i2"}}},
		{6, DEL, "vm1", "", "", 1, "", []assignment{{"rg1", "i1"}}},
		{7, DEL, "vm1", "", "", 0, "", []assignment{{"rg1", "i1"}}},
		{8, DEL, "vm1", "", "", 2, "", []assignment(nil)},
		{9, DEL, "vm1", "", "", 2, "", []assignment(nil)},
	}

	for _, test := range tests {
		i, err := loadIdentityAssignment(context.Background(), test.vm, s)
		ok(t, err)
		switch test.op {
		case ADD:
			uuid, err := i.add(test.resourceGroup, test.identity)
			test.assignedID = uuid
			ok(t, err)
		case DEL:
			i.remove(tests[test.deleteIndex].assignedID)
		}
		err = storeIdentityAssignment(context.Background(), test.vm, i, s)
		ok(t, err)
		i, err = loadIdentityAssignment(context.Background(), test.vm, s)
		ok(t, err)
		equal(t, test.identitySet, i.slice())
	}
}
