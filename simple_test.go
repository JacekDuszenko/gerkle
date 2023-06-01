package gerkle

import (
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateEmptyTree(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}

	_, err := NewSimpleMerkleTree(config, nil)

	assert.Equal(t, err, &EmptyTreeDataError{})
}
