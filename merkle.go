package gerkle

import (
	"hash"
)

type MerkleTreeConfig struct {
	hashingAlgorithmFactory func() hash.Hash
}

type MerkleTree interface {
	GetMerkleProof(data []byte) ([][]byte, error)

	VerifyMerkleProof(data []byte, proof [][]byte) (bool, error)

	UpdateLeaf(oldData []byte, newData []byte) error

	GetRoot() *Node
}

type Node struct {
	Left   *Node
	Right  *Node
	Parent *Node

	Hash []byte
	data []byte
}
