// Package gerkle provides the merkle tree implementation
package gerkle

import (
	"bytes"
	"hash"
)

// simpleMerkleTree is a simple iterative implementation of a Merkle tree.
type simpleMerkleTree struct {
	config        MerkleTreeConfig
	Root          *Node
	leafsByHashes map[string]*Node
}

// EmptyTreeDataError represents an attempt of creating an empty Merkle tree.
type EmptyTreeDataError struct {
}

func (r *EmptyTreeDataError) Error() string {
	return "Provide a non-empty slice of data to create a valid merkle tree"
}

// EmptyMerkleProofError represents an attempt of verifying an empty Merkle proof
type EmptyMerkleProofError struct {
}

func (r *EmptyMerkleProofError) Error() string {
	return "Provide a non-empty merkle proof to verify it"
}

// DataNotInMerkleTreeError signals a behaviour of modifying, updating,
// or trying to generate a proof for a data that is not present in the Merkle tree.
type DataNotInMerkleTreeError struct {
}

func (r *DataNotInMerkleTreeError) Error() string {
	return "Provided data is not part of merkle tree, proof for it cannot be generated"
}

// UpdateWithNilDataError signals a behaviour of updating a tree element with nil data
type UpdateWithNilDataError struct {
}

func (r *UpdateWithNilDataError) Error() string {
	return "Provided data is can't be nil"
}

// UpdateWithExistingDataError signals a behaviour of updating a tree element
// with an element that already exists in the tree.
type UpdateWithExistingDataError struct {
}

func (r *UpdateWithExistingDataError) Error() string {
	return "The new value already exists in the merkle tree, update is not possible"
}

// NewSimpleMerkleTree creates the Merkle tree from a non-empty slice of bytes.
// Each element becomes a leaf in the tree. A proof of existence of each element can be issued
func NewSimpleMerkleTree(config MerkleTreeConfig, data [][]byte) (MerkleTree, error) {
	if len(data) == 0 {
		return nil, &EmptyTreeDataError{}
	}
	tree := &simpleMerkleTree{config: config}
	leafNodes := tree.createLeafNodes(data, tree.config)
	buildTreeFromLeafs(tree, leafNodes)

	return tree, nil
}

// GetRoot retrieves a root node of a Merkle tree
func (s *simpleMerkleTree) GetRoot() *Node {
	return s.Root
}

// GetMerkleProof creates a Merkle proof for a given tree leaf element.
// If given data does not exist in the tree, the error is returned.
func (s *simpleMerkleTree) GetMerkleProof(data []byte) ([][]byte, error) {
	results := make([][]byte, 0)
	node, ok := s.leafsByHashes[string(calculateHashFromData(data, s.config))]
	if !ok {
		return nil, &DataNotInMerkleTreeError{}
	}

	for node.Parent != nil {
		if node.Parent.Left == node {
			results = append(results, node.Parent.Right.Hash)
		} else {
			results = append(results, node.Parent.Left.Hash)
		}
		node = node.Parent
	}
	return results, nil
}

// VerifyMerkleProof checks whether given Merkle proof asserts
// the presence of a given element in the Merkle tree.
func (s *simpleMerkleTree) VerifyMerkleProof(data []byte, merkleProof [][]byte) (bool, error) {
	if len(merkleProof) == 0 {
		return false, &EmptyMerkleProofError{}
	}
	h := s.config.hashingAlgorithmFactory()
	h.Write(data)
	dataHash := h.Sum(nil)
	for _, nodeHash := range merkleProof {
		dataHash = hashInOrder(s.config.hashingAlgorithmFactory(), dataHash, nodeHash)
	}

	return bytes.Equal(dataHash, s.Root.Hash), nil
}

// UpdateLeaf allows for efficient updating of an existing element in the tree.
// Updates with data that already exist in the tree are not allowed. If such data is passed as newData argument,
// the UpdateWithExistingDataError error is returned. Updates with nil data is not allowed.
func (s *simpleMerkleTree) UpdateLeaf(oldData []byte, newData []byte) error {
	if newData == nil {
		return &UpdateWithNilDataError{}
	}
	newHash := calculateHashFromData(newData, s.config)
	if _, ok := s.leafsByHashes[string(newHash)]; ok {
		return &UpdateWithExistingDataError{}
	}
	oldHash := string(calculateHashFromData(oldData, s.config))
	node, ok := s.leafsByHashes[oldHash]
	if !ok {
		return &DataNotInMerkleTreeError{}
	}

	delete(s.leafsByHashes, oldHash)
	s.leafsByHashes[string(newHash)] = node

	// Check whether node was paired with a dupe
	if node.Parent != nil && bytes.Equal(node.Parent.Left.Hash, node.Parent.Right.Hash) {
		node.Parent.Left = node
		node.Parent.Right = node
	}

	node.data = newData
	node.Hash = newHash

	for node.Parent != nil {
		node.Parent.Hash = hashInOrder(
			s.config.hashingAlgorithmFactory(),
			node.Parent.Left.Hash,
			node.Parent.Right.Hash,
		)
		node = node.Parent
	}
	return nil
}

func hashInOrder(hashingAlgorithm hash.Hash, first []byte, second []byte) []byte {
	if bytes.Compare(first, second) == 1 {
		first, second = second, first
	}
	hashingAlgorithm.Write(first)
	hashingAlgorithm.Write(second)

	return hashingAlgorithm.Sum(nil)
}

func (s *simpleMerkleTree) createLeafNodes(data [][]byte, config MerkleTreeConfig) []*Node {
	s.leafsByHashes = make(map[string]*Node)
	var nodes []*Node
	for _, d := range data {
		nodeHash := calculateHashFromData(d, config)
		node := &Node{data: d, Hash: nodeHash}
		nodes = append(nodes, node)
		s.leafsByHashes[string(nodeHash)] = node
	}
	if len(nodes)%2 != 0 {
		lastNode := nodes[len(nodes)-1]
		nodes = append(nodes, &Node{data: lastNode.data, Hash: lastNode.Hash})
	}
	return nodes
}

func buildTreeFromLeafs(tree *simpleMerkleTree, leafNodes []*Node) {
	currentLevel := leafNodes
	var nextLevel []*Node
	for {
		for i := 0; i < len(currentLevel); i += 2 {
			left, right := currentLevel[i], currentLevel[i+1]
			parent := &Node{
				Left:  left,
				Right: right,
				Hash:  hashInOrder(tree.config.hashingAlgorithmFactory(), left.Hash, right.Hash),
			}
			left.Parent = parent
			right.Parent = parent
			nextLevel = append(nextLevel, parent)
		}
		if len(nextLevel) == 1 {
			tree.Root = nextLevel[0]
			tree.Root.Parent = nil
			return
		}
		if len(nextLevel)%2 != 0 {
			lastNode := nextLevel[len(nextLevel)-1]
			nextLevel = append(nextLevel, &Node{Hash: lastNode.Hash})
		}
		currentLevel = make([]*Node, len(nextLevel))
		copy(currentLevel, nextLevel)
		nextLevel = nil
	}
}

func calculateHashFromData(data []byte, treeConfig MerkleTreeConfig) []byte {
	h := treeConfig.hashingAlgorithmFactory()
	h.Write(data)
	return h.Sum(nil)
}
