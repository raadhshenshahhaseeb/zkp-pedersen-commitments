package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

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

func getBlindingFactor(blindingScalars []*big.Int, u *big.Int) *big.Int {
	constant := new(big.Int).Set(blindingScalars[0])

	linear := new(big.Int).Mul(blindingScalars[1], u)

	quadratic := new(big.Int).Mul(blindingScalars[2], new(big.Int).Mul(u, u))

	pi := new(big.Int).Add(constant, linear)
	pi.Add(pi, quadratic)

	return pi
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

type CommitmentWithBlinding struct {
	Commitment     ECPoint
	BlindingScalar *big.Int
}

type PolynomialCommitments struct {
	Commitments []CommitmentWithBlinding
	Hash        []byte
}

func prover(generator ECPoint, blinding ECPoint, curve elliptic.Curve) {
	polynomials := getPolynomials()

	var polynomialCommitmentData []PolynomialCommitments

	for _, polynomial := range polynomials {
		var polynomialCommitments []CommitmentWithBlinding
		for _, coeff := range polynomial {
			blindingScalar := randomFieldElement(curve)
			commitment := commit(coeff, blindingScalar, generator, blinding, curve)
			polynomialCommitments = append(polynomialCommitments, CommitmentWithBlinding{
				Commitment:     commitment,
				BlindingScalar: blindingScalar,
			})
		}

		// Hash the commitments for the current polynomial
		var commitments []ECPoint
		for _, c := range polynomialCommitments {
			commitments = append(commitments, c.Commitment)
		}
		commitmentsHash := hashCommitments(commitments)

		// Store the commitments and the hash
		polynomialCommitmentData = append(polynomialCommitmentData, PolynomialCommitments{
			Commitments: polynomialCommitments,
			Hash:        commitmentsHash,
		})
	}

	// Assuming polynomialCommitmentData contains all the PolynomialCommitments structs
	var allCommitmentsForPolynomials [][]ECPoint

	for _, polyCommitData := range polynomialCommitmentData {
		var commitments []ECPoint
		for _, commitmentWithBlinding := range polyCommitData.Commitments {
			commitments = append(commitments, commitmentWithBlinding.Commitment)
		}
		allCommitmentsForPolynomials = append(allCommitmentsForPolynomials, commitments)
	}

	// Now allCommitmentsForPolynomials is a slice of slices where each inner slice contains the ECPoints (commitments) for a polynomial

	var challenges []*big.Int
	// polyEvalRes holds results of polynomial evauluations at a scalar challenge u
	var polyEvalRes []*big.Int
	var combinedCommitments []ECPoint
	for i, data := range polynomialCommitmentData {
		challenges = append(challenges, challenge(curve, data.Hash))
		polyEvalRes = append(polyEvalRes, polynomialEvaluation(challenges[i], polynomials[i]))
		combinedCommitments = append(combinedCommitments, combineCommitments(allCommitmentsForPolynomials[i], challenges[i], curve))
	}

}

// this function is for testing purposes, probably will turn it into testcase
func check(points []ECPoint, blinding, generator ECPoint, curve elliptic.Curve, fu *big.Int) {
	c0 := points[0]
	c1x, c1y := curve.ScalarMult(points[1].X, points[1].Y, big.NewInt(10).Bytes())
	u2Sq := new(big.Int).Mul(big.NewInt(10), big.NewInt(10))
	c2x, c2y := curve.ScalarMult(points[2].X, points[2].Y, u2Sq.Bytes())

	t1, t2 := curve.Add(c2x, c2y, c1x, c1y)
	x, y := curve.Add(c0.X, c0.Y, t1, t2)

	piBx, piBy := curve.ScalarMult(blinding.X, blinding.Y, big.NewInt(111).Bytes())

	negXy := new(big.Int).Neg(piBy)
	_negXy := new(big.Int).Mod(negXy, curve.Params().P)

	a1, a2 := curve.Add(x, y, piBx, _negXy)

	fgx, fgy := curve.ScalarMult(generator.X, generator.Y, fu.Bytes())

	if a1.Cmp(fgx) == 0 && a2.Cmp(fgy) == 0 {
		fmt.Println("holds")
	} else {
		fmt.Println("a1: ", a1)
		fmt.Println("a2: ", a2)
		fmt.Println("fgx: ", fgx)
		fmt.Println("fgy: ", fgy)
	}
}

func polynomialEvaluation(u *big.Int, polynomial []*big.Int) *big.Int {
	v0 := polynomial[0]
	v1 := new(big.Int).Mul(polynomial[1], u)
	v2 := new(big.Int).Mul(polynomial[2], new(big.Int).Mul(u, u))

	return new(big.Int).Add(v0, new(big.Int).Add(v1, v2))
}

func combineCommitments(commitments []ECPoint, value *big.Int, curve elliptic.Curve) ECPoint {
	if len(commitments) < 3 {
		panic("combineCommitments requires at least 3 ECPoints in the slice")
	}

	// Scalar multiplication with the first and second points
	tempCx1, tempCy1 := curve.ScalarMult(commitments[1].X, commitments[1].Y, value.Bytes())

	// Calculate value^2 once and reuse
	valueSquared := new(big.Int).Mul(value, value)
	tempCx2, tempCy2 := curve.ScalarMult(commitments[2].X, commitments[2].Y, valueSquared.Bytes())

	tempCommitmentX, tempCommitmentY := curve.Add(commitments[0].X, commitments[0].Y, tempCx1, tempCy1)
	commitmentX, commitmentY := curve.Add(tempCommitmentX, tempCommitmentY, tempCx2, tempCy2)

	// Return the new combined commitment point
	return ECPoint{
		X: commitmentX,
		Y: commitmentY,
	}
}

func commit(value, blindingScalar *big.Int, generator, blinding ECPoint, curve elliptic.Curve) ECPoint {
	gX, gY := curve.ScalarMult(generator.X, generator.Y, value.Bytes())

	commX, commY := curve.Add(gX, gY, blinding.X, blinding.Y)

	return ECPoint{
		X: commX,
		Y: commY,
	}
}
