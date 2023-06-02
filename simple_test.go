package gerkle

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSimpleMerkleTree_Empty(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}

	_, err := NewSimpleMerkleTree(config, nil)

	assert.Equal(t, err, &EmptyTreeDataError{})
}

func TestNewSimpleMerkleTree_SingleLeaf(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	byteData := []byte("test data")
	expectedMerkleRoot := []byte{
		0xaf, 0x8e, 0xdf, 0x93, 0xaa,
		0x32, 0xf9, 0x88, 0xf5, 0x91,
		0x17, 0x24, 0xf5, 0x91, 0xab,
		0x53, 0x25, 0x72, 0x28, 0x3,
		0xbb, 0x13, 0x8, 0x76, 0xb5,
		0x3, 0x12, 0x82, 0x5d, 0x50,
		0x7, 0x0,
	}

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

func TestNewSimpleMerkleTree_TwoLeafs(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	byteData := [][]byte{[]byte("test data first"), []byte("test data second")}

	tree, err := NewSimpleMerkleTree(config, byteData)

	assert.Nil(t, err)
	assert.Nil(t, tree.GetRoot().Parent)
	assert.Nil(t, tree.GetRoot().data)
	assert.Nil(t, tree.GetRoot().Left.Left)
	assert.Nil(t, tree.GetRoot().Left.Right)
	assert.Nil(t, tree.GetRoot().Right.Left)
	assert.Nil(t, tree.GetRoot().Right.Right)

	assert.Equal(t, tree.GetRoot().Left.data, byteData[0])
	assert.Equal(t, tree.GetRoot().Right.data, byteData[1])
}

// Checks whether two nodes that appear in different order produce the same hash
// The sorting property is important to generate correct Merkle proofs
func TestNewSimpleMerkleTree_DifferentOrderOfNodes(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	byteDataFirst := [][]byte{[]byte("one"), []byte("two")}
	byteDataSecond := [][]byte{[]byte("two"), []byte("one")}

	firstTree, firstErr := NewSimpleMerkleTree(config, byteDataFirst)
	secondTree, secondErr := NewSimpleMerkleTree(config, byteDataSecond)
	assert.Nil(t, firstErr)
	assert.Nil(t, secondErr)

	assert.Equal(t, firstTree.GetRoot().Hash, secondTree.GetRoot().Hash)
}

func TestSimpleMerkleTree_VerifyMerkleProof_Empty(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two")}
	tree, _ := NewSimpleMerkleTree(config, data)

	correct, err := tree.VerifyMerkleProof(data[0], nil)

	assert.False(t, correct)
	assert.Equal(t, &EmptyMerkleProofError{}, err)
}

func TestSimpleMerkleTree_VerifyMerkleProof_Invalid(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("four"), []byte("five")}
	tree, _ := NewSimpleMerkleTree(config, data)

	invalidProof := [][]byte{{0x53, 0x54}, {0x23, 0xff}}

	correct, err := tree.VerifyMerkleProof(data[0], invalidProof)

	assert.False(t, correct)
	assert.Nil(t, err)
}

func TestSimpleMerkleTree_VerifyMerkleProof_TwoElements(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two")}
	tree, _ := NewSimpleMerkleTree(config, data)

	h := config.hashingAlgorithmFactory()
	h.Write(data[0])
	hashOfFirstElement := h.Sum(nil)

	correct, err := tree.VerifyMerkleProof(data[1], [][]byte{hashOfFirstElement})
	assert.True(t, correct)
	assert.Nil(t, err)

	h2 := config.hashingAlgorithmFactory()
	h2.Write(data[1])
	hashOfSecondElement := h2.Sum(nil)

	correct, err = tree.VerifyMerkleProof(data[0], [][]byte{hashOfSecondElement})
	assert.True(t, correct)
	assert.Nil(t, err)
}

func TestSimpleMerkleTree_VerifyMerkleProof_MultipleElements(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("four"), []byte("five")}
	tree, _ := NewSimpleMerkleTree(config, data)

	proofForFirstElement := [][]byte{tree.GetRoot().Left.Left.Right.Hash, tree.GetRoot().Left.Right.Hash, tree.GetRoot().Right.Hash}

	correct, err := tree.VerifyMerkleProof(data[0], proofForFirstElement)

	assert.True(t, correct)
	assert.Nil(t, err)

	proofForOddElement := [][]byte{tree.GetRoot().Right.Left.Right.Hash, tree.GetRoot().Right.Right.Hash, tree.GetRoot().Left.Hash}

	correct, err = tree.VerifyMerkleProof(data[4], proofForOddElement)

	assert.True(t, correct)
	assert.Nil(t, err)
}

func TestSimpleMerkleTree_GetMerkleProof_UnknownData(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one")}
	tree, _ := NewSimpleMerkleTree(config, data)

	proof, err := tree.GetMerkleProof([]byte("two"))

	assert.Nil(t, proof)
	assert.Equal(t, &DataNotInMerkleTreeError{}, err)
}

func TestSimpleMerkleTree_GetMerkleProof_Nil(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one")}
	tree, _ := NewSimpleMerkleTree(config, data)

	proof, err := tree.GetMerkleProof(nil)

	assert.Nil(t, proof)
	assert.Equal(t, &DataNotInMerkleTreeError{}, err)
}

func TestSimpleMerkleTree_GetMerkleProof_TwoNodes(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two")}
	tree, _ := NewSimpleMerkleTree(config, data)

	firstProof, firstErr := tree.GetMerkleProof([]byte("one"))
	secondProof, secondErr := tree.GetMerkleProof([]byte("two"))
	assert.Nil(t, firstErr)
	assert.Nil(t, secondErr)
	assert.Equal(t, [][]byte{tree.GetRoot().Right.Hash}, firstProof)
	assert.Equal(t, [][]byte{tree.GetRoot().Left.Hash}, secondProof)
}

func TestSimpleMerkleTree_GetMerkleProof_OneNode(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one")}
	tree, _ := NewSimpleMerkleTree(config, data)

	proof, err := tree.GetMerkleProof([]byte("one"))
	assert.Nil(t, err)

	// Verify two cases to check if duplicate node was created properly
	assert.Equal(t, [][]byte{tree.GetRoot().Right.Hash}, proof)
	assert.Equal(t, [][]byte{tree.GetRoot().Left.Hash}, proof)
}

func TestSimpleMerkleTree_GetMerkleProof_MultipleNodes(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("four"), []byte("five")}
	tree, _ := NewSimpleMerkleTree(config, data)

	proof, err := tree.GetMerkleProof([]byte("one"))

	assert.Nil(t, err)
	assert.Equal(t, [][]byte{tree.GetRoot().Left.Left.Right.Hash, tree.GetRoot().Left.Right.Hash, tree.GetRoot().Right.Hash}, proof)
}

func TestSimpleMerkleTree_UpdateLeaf_NilNewData(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one")}
	tree, _ := NewSimpleMerkleTree(config, data)

	err := tree.UpdateLeaf([]byte("one"), nil)

	assert.Equal(t, &UpdateWithNilDataError{}, err)
}

func TestSimpleMerkleTree_UpdateLeaf_UnknownData(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one")}
	tree, _ := NewSimpleMerkleTree(config, data)

	err := tree.UpdateLeaf([]byte("unknown"), []byte("two"))

	assert.Equal(t, &DataNotInMerkleTreeError{}, err)
}

func TestSimpleMerkleTree_UpdateLeaf_NewDataAlreadyExists(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two")}
	tree, _ := NewSimpleMerkleTree(config, data)

	err := tree.UpdateLeaf([]byte("one"), []byte("two"))

	assert.Equal(t, &UpdateWithExistingDataError{}, err)
}

func TestSimpleMerkleTree_UpdateLeaf_SingleNode(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one")}
	tree, _ := NewSimpleMerkleTree(config, data)

	err := tree.UpdateLeaf([]byte("one"), []byte("two"))

	assert.Nil(t, err)

	assert.Equal(t, tree.GetRoot().Left.data, []byte("two"))
	// Check right node to verify if duplicate node data changes as well
	assert.Equal(t, tree.GetRoot().Right.data, []byte("two"))

	proof, err := tree.GetMerkleProof([]byte("two"))
	assert.Nil(t, err)
	correct, err := tree.VerifyMerkleProof([]byte("two"), proof)
	assert.True(t, correct)
	assert.Nil(t, err)
}

func TestSimpleMerkleTree_UpdateLeaf_DoubleUpdate(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one")}
	tree, _ := NewSimpleMerkleTree(config, data)

	err := tree.UpdateLeaf([]byte("one"), []byte("two"))
	err = tree.UpdateLeaf([]byte("two"), []byte("three"))

	assert.Equal(t, tree.GetRoot().Left.data, []byte("three"))
	// Check right node to verify if duplicate node data changes as well
	assert.Equal(t, tree.GetRoot().Right.data, []byte("three"))

	proof, err := tree.GetMerkleProof([]byte("three"))
	assert.Nil(t, err)
	correct, err := tree.VerifyMerkleProof([]byte("three"), proof)
	assert.True(t, correct)
	assert.Nil(t, err)

	// old updated element is not present anymore
	proof, err = tree.GetMerkleProof([]byte("two"))
	assert.Nil(t, proof)
	assert.Equal(t, &DataNotInMerkleTreeError{}, err)
}

func TestSimpleMerkleTree_UpdateLeaf_MultipleNodes(t *testing.T) {
	config := MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}
	data := [][]byte{[]byte("one"), []byte("two"), []byte("three"), []byte("four"), []byte("five")}
	tree, _ := NewSimpleMerkleTree(config, data)

	err := tree.UpdateLeaf([]byte("three"), []byte("testing"))

	assert.Nil(t, err)

	assert.Equal(t, tree.GetRoot().Left.Right.Left.data, []byte("testing"))

	proof, err := tree.GetMerkleProof([]byte("testing"))
	assert.Nil(t, err)
	correct, err := tree.VerifyMerkleProof([]byte("testing"), proof)
	assert.True(t, correct)
	assert.Nil(t, err)
}
