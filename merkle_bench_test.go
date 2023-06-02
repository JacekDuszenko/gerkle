package gerkle

import (
	"crypto/sha256"
	"testing"

	fuzz "github.com/google/gofuzz"
)

func benchmarkSimpleMerkleTree(datasetSize int, b *testing.B) {
	fuzzer := fuzz.New().NumElements(datasetSize, datasetSize+1).NilChance(0.0)
	var data [][]byte
	fuzzer.Fuzz(&data)
	for n := 0; n < b.N; n++ {
		tree, _ := NewSimpleMerkleTree(MerkleTreeConfig{hashingAlgorithmFactory: sha256.New}, data)
		proof, _ := tree.GetMerkleProof(data[0])
		_, _ = tree.VerifyMerkleProof(data[0], proof)
	}
}

func BenchmarkSimpleMerkleTree10(b *testing.B) {
	benchmarkSimpleMerkleTree(10, b)
}

func BenchmarkSimpleMerkleTree1000(b *testing.B) {
	benchmarkSimpleMerkleTree(1000, b)
}

func BenchmarkSimpleMerkleTree10K(b *testing.B) {
	benchmarkSimpleMerkleTree(10000, b)
}

func BenchmarkSimpleMerkleTree100K(b *testing.B) {
	benchmarkSimpleMerkleTree(100_000, b)
}

func BenchmarkSimpleMerkleTree1M(b *testing.B) {
	benchmarkSimpleMerkleTree(1_000_000, b)
}
