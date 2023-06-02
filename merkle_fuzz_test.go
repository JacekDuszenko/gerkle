package gerkle

import (
	"crypto/sha256"
	"testing"

	fuzz "github.com/google/gofuzz"
)

func FuzzSimpleMerkleTree(f *testing.F) {
	//testcases := [][][]byte{
	//	{[]byte("abc"), []byte("def")},
	//	{[]byte("ghi"), []byte("jkl")},
	//}
	//for _, tc := range testcases {
	//	f.Add(tc) // Use f.Add to provide a seed corpus
	//}
	f.Fuzz(func(t *testing.T, _ int) {
		var data [][]byte
		fuzzer := fuzz.New()
		fuzzer.Fuzz(&data)
		tree, err := NewSimpleMerkleTree(MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}, data)
		if err != nil && err.Error() != "Provide a non-empty slice of data to create a valid merkle tree" {
			t.Errorf("Tree creation resulted with an error %q", err)
		}
		for _, elem := range data {
			proof, err := tree.GetMerkleProof(elem)
			if err != nil {
				t.Errorf("Generating a Merkle proof resulted with an error %q", err)
			}
			proofResult, err := tree.VerifyMerkleProof(elem, proof)
			if err != nil {
				t.Errorf("Verifying a Merkle proof resulted with an error %q", err)
			}
			if !proofResult {
				t.Errorf("Verifying a Merkle proof failed. The element is: %q", elem)
			}
		}
	})
}
