package gerkle

import (
	"bytes"
	"hash"
)

type simpleMerkleTree struct {
	config        MerkleTreeConfig
	Root          *Node
	leafsByHashes map[string]*Node
}

type EmptyTreeDataError struct {
}

func (r *EmptyTreeDataError) Error() string {
	return "Provide a non-empty slice of data to create a valid merkle tree"
}

type EmptyMerkleProofError struct {
}

func (r *EmptyMerkleProofError) Error() string {
	return "Provide a non-empty merkle proof to verify it"
}

type DataNotInMerkleTreeError struct {
}

func (r *DataNotInMerkleTreeError) Error() string {
	return "Provided data is not part of merkle tree, proof for it cannot be generated"
}

func NewSimpleMerkleTree(config MerkleTreeConfig, data [][]byte) (MerkleTree, error) {
	if len(data) == 0 {
		return nil, &EmptyTreeDataError{}
	}
	tree := &simpleMerkleTree{config: config}
	leafNodes := tree.createLeafNodes(data, tree.config)
	buildTreeFromLeafs(tree, leafNodes)

	return tree, nil
}

func (s *simpleMerkleTree) GetRoot() *Node {
	return s.Root
}

func (s *simpleMerkleTree) GetMerkleProof(data []byte) ([][]byte, error) {
	if data == nil {

	}
	results := make([][]byte, 0)
	dataHash := string(getHashFromData(data, s.config))
	node, ok := s.leafsByHashes[dataHash]
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

func hashInOrder(hashingAlgorithm hash.Hash, first []byte, second []byte) []byte {
	if bytes.Compare(first, second) == 1 {
		first, second = second, first
	}
	hashingAlgorithm.Write(first)
	hashingAlgorithm.Write(second)

	return hashingAlgorithm.Sum(nil)
}

func (s *simpleMerkleTree) UpdateLeaf(oldHash []byte, newHash []byte) error {
	//TODO implement me
	panic("implement me")
}

func (s *simpleMerkleTree) createLeafNodes(data [][]byte, config MerkleTreeConfig) []*Node {
	s.leafsByHashes = make(map[string]*Node)
	var nodes []*Node
	for _, d := range data {
		nodeHash := getHashFromData(d, config)
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
			parent := &Node{Left: left, Right: right, Hash: hashInOrder(tree.config.hashingAlgorithmFactory(), left.Hash, right.Hash)}
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

func getHashFromData(data []byte, treeConfig MerkleTreeConfig) []byte {
	h := treeConfig.hashingAlgorithmFactory()
	h.Write(data)
	return h.Sum(nil)
}
