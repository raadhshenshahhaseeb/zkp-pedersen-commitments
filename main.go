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

	for i, point := range points {
		fmt.Printf("Point %d: (%s, %s)\n", i+1, point.X.Text(10), point.Y.Text(10))
	}

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

// P256CurveOrder is the order of the P-256 curve
var P256CurveOrder, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)

// RandomBigInt generates a random number in the range [1, curveOrder-1]
func RandomBigInt() *big.Int {
	// Define the upper limit as curveOrder - 1
	max := new(big.Int).Sub(P256CurveOrder, big.NewInt(1))

	// Generate a random number between 1 and max
	randNum, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}

	// Ensure the number is at least 1
	randNum.Add(randNum, big.NewInt(1))
	return randNum
}
