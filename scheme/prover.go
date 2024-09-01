package scheme

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

func getPolynomials() [][]*big.Int {
	fx := []*big.Int{
		big.NewInt(4), // f_0
		big.NewInt(2), // f_1.x
		big.NewInt(6), // f_2.x^2
	}

	gx := []*big.Int{
		big.NewInt(3), // g_0
		big.NewInt(1), // g_1.x
		big.NewInt(7), // g_2.x^2
	}

	hx := []*big.Int{
		big.NewInt(3), // h_0
		big.NewInt(5), // h_1.x
		big.NewInt(2), // h_2.x^2
	}

	return [][]*big.Int{fx, gx, hx}
}

func Prover(generator ECPoint, blinding ECPoint, curve elliptic.Curve) {
	polynomials := getPolynomials()
	var combineCommitments []ECPoint
	var u []*big.Int

	for _, polynomial := range polynomials {
		holds, combinedCommitment, challengeU := evaluate(polynomial, curve, generator, blinding)
		if holds {
			fmt.Println("commitment for polynomial holds")
		}
		combineCommitments = append(combineCommitments, combinedCommitment)
		u = append(u, challengeU)
	}

	verified := VerifyRelation(combineCommitments[0], combineCommitments[1], combineCommitments[2], curve, new(big.Int).Add(new(big.Int).Add(u[0], u[1]), u[2]))
	if verified {
		fmt.Println("commitment relation verified")
	} else {
		fmt.Println("commitment relation not verified")
	}
}

func evaluate(polynomial []*big.Int, curve elliptic.Curve, generator, blinding ECPoint) (bool, ECPoint, *big.Int) {
	var commitments []ECPoint
	var blindingScalars []*big.Int

	for _, coeff := range polynomial {
		blindingS := randomFieldElement(curve)
		commitments = append(commitments, commit(coeff, blindingS, generator, blinding, curve))
		blindingScalars = append(blindingScalars, blindingS)
	}

	// u is a challenge scalar computed from the hash of commitments
	u := challenge(curve, hashCommitments(commitments))

	evaluatedPolynomial := polynomialEvaluation(u, polynomial)

	// pi is the computed blinding factor computed using pi = u^2.gamma + u.beta + alpha which are the blinding Scalars for the polynomial
	pi := getBlindingFactor(blindingScalars, u)

	combinedCommitment := combineCommitments(commitments, u, curve)

	return VerifyEquation(curve, generator, blinding, pi, evaluatedPolynomial, combinedCommitment), combinedCommitment, u

}

func commit(coeff, blindingS *big.Int, generatorP, blindingP ECPoint, curve elliptic.Curve) ECPoint {
	// e.g. : f_0 . G
	gX, gY := curve.ScalarMult(generatorP.X, generatorP.Y, coeff.Bytes())

	// e.g. : alpha . B
	bX, bY := curve.ScalarMult(blindingP.X, blindingP.Y, blindingS.Bytes())

	commitmentX, commitmentY := curve.Add(gX, gY, bX, bY)

	return ECPoint{X: commitmentX, Y: commitmentY}
}

func randomFieldElement(curve elliptic.Curve) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Sub(curve.Params().P, big.NewInt(1)))
	if err != nil {
		return nil
	}

	return n.Add(n, big.NewInt(1))
}

// Function to hash the commitments for a polynomial
func hashCommitments(commitments []ECPoint) []byte {
	hasher := sha256.New()

	for _, commitment := range commitments {
		hasher.Write(commitment.X.Bytes())
		hasher.Write(commitment.Y.Bytes())
	}

	return hasher.Sum(nil)
}

func getBlindingFactor(blindingScalars []*big.Int, u *big.Int) *big.Int {
	constant := new(big.Int).Set(blindingScalars[0])

	linear := new(big.Int).Mul(blindingScalars[1], u)

	quadratic := new(big.Int).Mul(blindingScalars[2], new(big.Int).Mul(u, u))

	pi := new(big.Int).Add(constant, linear)
	pi.Add(pi, quadratic)

	return pi
}

func polynomialEvaluation(u *big.Int, polynomial []*big.Int) *big.Int {
	v0 := polynomial[0]
	v1 := new(big.Int).Mul(polynomial[1], u)
	v2 := new(big.Int).Mul(polynomial[2], new(big.Int).Mul(u, u))

	return new(big.Int).Add(v0, new(big.Int).Add(v1, v2))
}

func combineCommitments(commitments []ECPoint, challenge *big.Int, curve elliptic.Curve) ECPoint {
	if len(commitments) < 3 {
		panic("combineCommitments requires at least 3 ECPoints in the slice")
	}

	// Scalar multiplication with the first and second points
	tempCx1, tempCy1 := curve.ScalarMult(commitments[1].X, commitments[1].Y, challenge.Bytes())

	// Calculate value^2 once and reuse
	valueSquared := new(big.Int).Mul(challenge, challenge)
	tempCx2, tempCy2 := curve.ScalarMult(commitments[2].X, commitments[2].Y, valueSquared.Bytes())

	tempCommitmentX, tempCommitmentY := curve.Add(commitments[0].X, commitments[0].Y, tempCx1, tempCy1)
	commitmentX, commitmentY := curve.Add(tempCommitmentX, tempCommitmentY, tempCx2, tempCy2)

	// Return the new combined commitment point
	return ECPoint{
		X: commitmentX,
		Y: commitmentY,
	}
}
