///////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2013 Jimmie Bergmann - jimmiebergmann@gmail.com
//
// This software is provided 'as-is', without any express or
// implied warranty. In no event will the authors be held
// liable for any damages arising from the use of this software.
// 
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute
// it freely, subject to the following restrictions:
// 
// 1. The origin of this software must not be misrepresented;
//    you must not claim that you wrote the original software.
//    If you use this software in a product, an acknowledgment
//    in the product documentation would be appreciated but
//    is not required.
// 
// 2. Altered source versions must be plainly marked as such,
//    and must not be misrepresented as being the original software.
// 
// 3. This notice may not be removed or altered from any
//    source distribution.
// 
///////////////////////////////////////////////////////////////////////////////////

#ifndef __RSA_HPP__
#define __RSA_HPP__

// Notes:
// 1.	We are using the srand and rand function from stdlib.h
//		but we could roll our own FASTER randomization function.
// 2.	I don't think you should [en][de]crypt any message that's larger than
//		the two primes that we are using to calculate n and z ( the primes p and q ).
// 3.	It's taking way too long time to calculate e and d when we are using high primes.
//		FIXED since EuclideanAlgorithm( ) was fixed?
// 4.	What happends when are getting out of range in EuclideanAlgorithm( ) ? Stuck in loop?
//		FIXED now by using unsigned ints instead?

// 32 bit version of RSA.
class RSA32
{

public:

	// Constructors
	RSA32( );
	RSA32( const unsigned int p_e, const unsigned int p_d, const unsigned int p_n );
	RSA32( const unsigned int p_e, const unsigned int p_d,
		const unsigned int p_n, const unsigned int p_z );

	// Initialization functions
	bool RandomizeKeys( const unsigned int p_seed ); // Randomly generate the keys.
	bool CalculateKeys( const unsigned int p_p, const unsigned int p_q ); // p_p and p_q must be 2 different primes.
	bool CalculatePublicKey( ); // Calculate the public key by using n and z which already should be set.
	bool CalculatePrivateKey( ); // Calculate the private key by using e, n and z which already should be set.
	bool CrackPrivateKey( ); // Requires e and n
	void Clear( ); // Clear all the varaibles.

	// Cryptographic functions
	unsigned int Encrypt( const unsigned int p_message );
	unsigned int Decrypt( const unsigned int p_message );
	

	// Set functions
	void SetE( const unsigned int p_e );
	void SetD( const unsigned int p_d );
	void SetP( const unsigned int p_p );
	void SetQ( const unsigned int p_q );
	void SetN( const unsigned int p_n );
	void SetZ( const unsigned int p_z );

	// Get functions
	unsigned int GetE( ) const;
	unsigned int GetD( ) const;
	unsigned int GetP( ) const;
	unsigned int GetQ( ) const;
	unsigned int GetN( ) const;
	unsigned int GetZ( ) const;

private:

	// Private functions
	void CalculateNZ( const unsigned int p_p, const unsigned int p_q ); // p and q should be 2 "large" primes.
	bool CalculateNZED( const unsigned int p_p, const unsigned int p_q ); // Combining the upper calculation functions.

	// Variable members.
	unsigned int m_e;	// Encryption key.
	unsigned int m_d; // Decryption key.
	unsigned int m_p; // Prime 1.
	unsigned int m_q; // Prime 2.
	unsigned int m_n; // Shared key = p * q
	unsigned int m_z; // Phi( n ) = ( p - 1 ) * ( q - 1 )

};

#endif