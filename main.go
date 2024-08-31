package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type ECPoint struct {
	X, Y *big.Int
}

func seeding() []byte {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		fmt.Println("Error generating seed:", err)
		return nil
	}

	return seed
}

func main() {
	curve := elliptic.P256()

	points := generateECPoints(seeding(), 3, curve)

	fmt.Println(curve.IsOnCurve(points[0].X, points[0].Y))
	fmt.Println(curve.IsOnCurve(points[1].X, points[1].Y))
	prover(points[0], points[1], curve)
}

func generateECPoints(seed []byte, n int, curve elliptic.Curve) []ECPoint {
	var points []ECPoint

	for i := 0; len(points) < n; i++ {
		// Create a new hash for each x value
		hashInput := append(seed, byte(i))
		// P is the order of the curve
		x := hashToBigInt(hashInput, curve.Params().P)

		y, yNeg := findYForX(curve, x)
		if y != nil {
			if randBit(seed) == 0 {
				points = append(points, ECPoint{X: new(big.Int).Set(x), Y: y})
			} else {
				points = append(points, ECPoint{X: new(big.Int).Set(x), Y: yNeg})
			}
		}
	}
	return points
}

func findYForX(curve elliptic.Curve, x *big.Int) (*big.Int, *big.Int) {
	xCubed := new(big.Int).Exp(x, big.NewInt(3), nil)
	a := big.NewInt(-3)
	aX := new(big.Int).Mul(a, x)
	rightSide := new(big.Int).Add(xCubed, aX)
	rightSide.Add(rightSide, curve.Params().B)
	rightSide.Mod(rightSide, curve.Params().P)

	y := new(big.Int).ModSqrt(rightSide, curve.Params().P)
	if y == nil {
		return nil, nil
	}
	yNeg := new(big.Int).Neg(y)
	yNeg.Mod(yNeg, curve.Params().P)
	return y, yNeg
}

func randBit(seed []byte) int {
	hash := sha256.Sum256(seed)
	return int(hash[0] & 1)
}

func hashToBigInt(data []byte, mod *big.Int) *big.Int {
	hash := sha256.Sum256(data)
	x := new(big.Int).SetBytes(hash[:])
	x.Mod(x, mod)
	return x
}

func randomFieldElement(curve elliptic.Curve) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Sub(curve.Params().P, big.NewInt(1)))
	if err != nil {
		return nil
	}

	return n.Add(n, big.NewInt(1))
}
