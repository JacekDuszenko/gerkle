package gerkle

import (
	"hash"
)

type MerkleTreeConfig struct {
	hashingAlgorithmFactory func() hash.Hash
}

type MerkleTree interface {
	GetMerkleProof(hash []byte) ([][]byte, error)

	VerifyMerkleProof(hash []byte, proof [][]byte) (bool, error)

	UpdateLeaf(oldHash []byte, newHash []byte) error

	GetRoot() *Node
}

type Node struct {
	Left   *Node
	Right  *Node
	Parent *Node

	Hash []byte
	data []byte
}
