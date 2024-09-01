package scheme

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func challenge(curve elliptic.Curve, hashedCommitment []byte) *big.Int {
	hasher := sha256.New()

	hasher.Write(hashedCommitment)

	finalHash := hasher.Sum(nil)

	blindingScalar, err := rand.Int(rand.Reader, curve.Params().P)
	if err != nil {
		return nil
	}

	hashPart := new(big.Int).SetBytes(finalHash)

	u := new(big.Int).Add(hashPart, blindingScalar)

	u.Mod(u, curve.Params().P)

	return u
}

func VerifyEquation(curve elliptic.Curve,
	generator, blinding ECPoint,
	pi, evaluatedPolynomial *big.Int,
	combinedCommitment ECPoint) bool {

	piBx, piBy := curve.ScalarMult(blinding.X, blinding.Y, pi.Bytes())

	negXy := new(big.Int).Neg(piBy)
	_negXy := new(big.Int).Mod(negXy, curve.Params().P)

	lhsX, lhsY := curve.Add(combinedCommitment.X, combinedCommitment.Y, piBx, _negXy)
	rhsX, rhsY := curve.ScalarMult(generator.X, generator.Y, evaluatedPolynomial.Bytes())

	var holds bool = false
	if rhsX.Cmp(lhsX) == 0 && rhsY.Cmp(lhsY) == 0 {
		fmt.Println("\nLHS")
		fmt.Println("lhsX: ", lhsX.String())
		fmt.Println("lhsY: ", lhsY.String())
		fmt.Println("\nRHS")
		fmt.Println("rhsX: ", rhsX.String())
		fmt.Println("rhsY: ", rhsY.String())
		fmt.Println("matched")
		holds = true
	} else {
		fmt.Println("LHS")
		fmt.Println("lhsX: ", lhsX.String())
		fmt.Println("lhsY: ", lhsY.String())
		fmt.Println("\nRHS")
		fmt.Println("rhsX: ", rhsX.String())
		fmt.Println("rhsY: ", rhsY.String())
		holds = false
	}

	return holds
}

func VerifyRelation(commitmentFu, commitmentGu, commitmentHu ECPoint, curve elliptic.Curve, u *big.Int) bool {
	// Assuming we have some operation that can combine points in a way that respects the underlying scalar multiplication
	// You might need a more advanced operation here, depending on how commitments are structured
	combinedX, combinedY := curve.ScalarMult(commitmentFu.X, commitmentFu.Y, u.Bytes())
	combinedX, combinedY = curve.Add(combinedX, combinedY, commitmentGu.X, commitmentGu.Y)

	return combinedX.Cmp(commitmentHu.X) == 0 && combinedY.Cmp(commitmentHu.Y) == 0
}
