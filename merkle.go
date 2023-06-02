// Package gerkle provides the merkle tree implementation
package gerkle

import (
	"hash"
)

// MerkleTreeConfig allows to specify an arbitrary hashing function factory
// used in Merkle tree.
type MerkleTreeConfig struct {
	hashingAlgorithmFactory func() hash.Hash
}

// MerkleTree specifies a set of methods for generating
// and verifying Merkle proofs.
//
// GetMerkleProof accepts bytes of data and creates a Merkle proof if the data is present in the tree.
// The proof can then be verified by VerifyMerkleProof,
// by passing a data existence of which is to be verified and the proof itself
// UpdateLeaf allows for efficient updates of the data inside the tree.
// Updating with a value that's already in the tree is not allowed
// GetRoot allows to get a reference to the root node of the tree.
type MerkleTree interface {
	GetMerkleProof(data []byte) ([][]byte, error)

	VerifyMerkleProof(data []byte, proof [][]byte) (bool, error)

	UpdateLeaf(oldData []byte, newData []byte) error

	GetRoot() *Node
}

// Node is a single element of a Merkle tree,
// it contains references to its parent and children.
type Node struct {
	Left   *Node // Left child of this node
	Right  *Node // Right child of this node
	Parent *Node // Parent of this node

	Hash []byte // Hash of this node
	data []byte // data of this node if the node is a leaf,
	// otherwise this field is nil for every intermediate node and root
}
