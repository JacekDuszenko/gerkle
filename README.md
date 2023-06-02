# gerkle

Implementation of merkle trees in Go.

# Testing

1. To run unit tests: `go test ./...`
2. To run fuzz tests: `go test -fuzz FuzzSimpleMerkleTree`.
Fuzzing run for some minutes and found no errors. Example logs:
```
fuzz: elapsed: 4m15s, execs: 23185113 (93547/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m18s, execs: 23472148 (95669/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m21s, execs: 23741894 (89895/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m24s, execs: 24030359 (96200/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m27s, execs: 24301048 (90216/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m30s, execs: 24491082 (63339/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m33s, execs: 24721713 (76888/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m36s, execs: 24991901 (90061/sec), new interesting: 33 (total: 34)
fuzz: elapsed: 4m39s, execs: 25253492 (87194/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 4m42s, execs: 25477484 (74646/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 4m45s, execs: 25728621 (83729/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 4m48s, execs: 25964852 (78760/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 4m51s, execs: 26172159 (69096/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 4m54s, execs: 26446731 (91523/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 4m57s, execs: 26737316 (96871/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 5m0s, execs: 27019736 (94138/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 5m3s, execs: 27277235 (85806/sec), new interesting: 34 (total: 35)
fuzz: elapsed: 5m6s, execs: 27578026 (100290/sec), new interesting: 34 (total: 35)
```

1. To run benchmark tests: `go test -bench=.`
Example output from bench testing:
```
goos: darwin
goarch: arm64
pkg: github.com/JacekDuszenko/gerkle
BenchmarkSimpleMerkleTree10-10      	  230812	      5458 ns/op
BenchmarkSimpleMerkleTree1000-10    	    1340	    876780 ns/op
BenchmarkSimpleMerkleTree10K-10     	       1	7266182292 ns/op
```