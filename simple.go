package gerkle

import "bytes"

type Node struct {
	Left   *Node
	Right  *Node
	Parent *Node

	Hash []byte
	data []byte
}

type SimpleMerkleTree struct {
	config MerkleTreeConfig
	Root   *Node
	leafs  []*Node
}

func (s SimpleMerkleTree) New(config MerkleTreeConfig, data [][]byte) MerkleTree {
	tree := &SimpleMerkleTree{config: config}
	leafNodes := s.createLeafNodes(data)
	buildTreeFromLeafs(tree, leafNodes)

	return tree
}

func buildTreeFromLeafs(tree *SimpleMerkleTree, leafNodes []*Node) {
	tree.leafs = leafNodes

	currentLevel := leafNodes
	var nextLevel []*Node
	for {
		for i := 0; i < len(currentLevel); i += 2 {
			left, right := currentLevel[i], currentLevel[i+1]
			if bytes.Compare(left.Hash, right.Hash) == 1 {
				left, right = right, left
			}
			h := tree.config.hashingAlgorithmFactory()
			h.Write(left.Hash)
			h.Write(right.Hash)
			parent := &Node{Left: left, Right: right, Hash: h.Sum(nil)}
			left.Parent = parent
			right.Parent = parent
			nextLevel = append(nextLevel, parent)
		}
		if len(nextLevel) == 1 {
			root := nextLevel[0]
			tree.Root = root
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

func (s SimpleMerkleTree) createLeafNodes(data [][]byte) []*Node {
	var nodes []*Node
	for _, d := range data {
		nodes = append(nodes, &Node{data: d, Hash: s.getHashFromData(d)})
	}
	if len(nodes)%2 != 0 {
		lastNode := nodes[len(nodes)-1]
		nodes = append(nodes, &Node{data: lastNode.data, Hash: lastNode.Hash})
	}
	return nodes
}

func (s SimpleMerkleTree) getHashFromData(data []byte) []byte {
	h := s.config.hashingAlgorithmFactory()
	h.Write(data)
	return h.Sum(nil)
}

func (s SimpleMerkleTree) GetMerkleProof(hash []byte) ([][]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (s SimpleMerkleTree) VerifyMerkleProof(hash []byte, proof [][]byte) bool {
	//TODO implement me
	panic("implement me")
}

func (s SimpleMerkleTree) UpdateLeaf(oldHash []byte, newHash []byte) error {
	//TODO implement me
	panic("implement me")
}
