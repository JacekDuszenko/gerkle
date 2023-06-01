package gerkle

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateEmptyTree(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}

	_, err := NewSimpleMerkleTree(config, nil)

	assert.Equal(t, err, &EmptyTreeDataError{})
}

func TestCreateTreeWithOneNode(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	byteData := []byte("test data")
	expectedMerkleRoot := []byte{0xaf, 0x8e, 0xdf, 0x93, 0xaa, 0x32, 0xf9, 0x88, 0xf5, 0x91, 0x17, 0x24, 0xf5, 0x91, 0xab, 0x53, 0x25, 0x72, 0x28, 0x3, 0xbb, 0x13, 0x8, 0x76, 0xb5, 0x3, 0x12, 0x82, 0x5d, 0x50, 0x7, 0x0}

	tree, err := NewSimpleMerkleTree(config, [][]byte{byteData})

	assert.Nil(t, err)
	assert.Nil(t, tree.GetRoot().Parent)
	assert.Nil(t, tree.GetRoot().data)
	assert.Nil(t, tree.GetRoot().Left.Left)
	assert.Nil(t, tree.GetRoot().Left.Right)

	// Check data
	assert.Equal(t, tree.GetRoot().Left.data, byteData)
	assert.Equal(t, tree.GetRoot().Right.data, byteData)

	// Check if two leaf nodes are identical, which means that
	// odd node was duplicated
	assert.Equal(t, tree.GetRoot().Left, tree.GetRoot().Right)

	assert.Equal(t, tree.GetRoot().Hash, expectedMerkleRoot)
}
