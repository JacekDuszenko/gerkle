package gerkle

import (
	"hash"
)

type MerkleTreeConfig struct {
	hashingAlgorithmFactory func() hash.Hash
}

type MerkleTree interface {
	GetMerkleProof(hash []byte) ([][]byte, error)

	VerifyMerkleProof(hash []byte, proof [][]byte) bool

	UpdateLeaf(oldHash []byte, newHash []byte) error
}
