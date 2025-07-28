package ptr_test

import (
	"testing"

	"github.com/openkcm/identity-management-plugins/pkg/utils/ptr"
	"github.com/stretchr/testify/assert"
)

func TestPointTo(t *testing.T) {
	t.Run("Should return pointer", func(t *testing.T) {
		type Test struct{}
		pointer := ptr.PointTo(Test{})
		assert.IsType(t, pointer, &Test{})
	})
}
