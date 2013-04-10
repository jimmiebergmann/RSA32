///////////////////////////////////////////////////////////////////////////////////
// RSA32 - Copyright (C) 2013 Jimmie Bergmann - jimmiebergmann@gmail.com
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

#include <RSA32.hpp>
#include <stdlib.h>
#include <cmath>

///////////////////////////////////////////////////////////////////////////////////
// General functions used that's being defined on the bottom of this file
unsigned int PowMod( unsigned int base, unsigned int exponent, unsigned int modulus );
unsigned int RandomNumber( unsigned int min, unsigned int max );
unsigned int RandomPrime( unsigned int min, unsigned int max );
//int EuclideanAlgorithm ( int a, int b ); // Euclid's algorithm
unsigned int EuclideanAlgorithm ( unsigned int a, unsigned int b ); // Euclid's algorithm
bool IsPrime( unsigned int number );

///////////////////////////////////////////////////////////////////////////////////
// Constructors
RSA32::RSA32( ) :
	e( 0 ),
	d( 0 ),
	n( 0 ),
	z( 0 )
{
}

RSA32::RSA32( unsigned int e, unsigned int d,
		 unsigned int n, unsigned int z ) :
	e( e ),
	d( d ),
	n( n ),
	z( z )
{
}

// Initialization functions
bool RSA32::RandomizeKeys( unsigned int seed )
{
	// You have to seed the rand function by yourself if you're not
	// providing any seed.
	if( seed != 0 )
	{
		srand( seed );
	}

	// Set p and q by generating random primes.
	unsigned int p = 0;
	unsigned int q = 0;

	// Do start at 46341 since it's closest to the lowest possible 32 bit number
	// by any number multiplied by itself. 46341^2 almost equals to the lowest 32 bit number...
	unsigned int prime_range_low = 46341; //32768;
	unsigned int prime_range_high = 65535;

	// Make sure that they're not equal to each other.
	while( p == q || p == 0 || q == 0 )
	{
		p = RandomPrime( prime_range_low, prime_range_high );
		q = RandomPrime( prime_range_low, prime_range_high );
	}

	// Calculate n, z, e and d by using two primes: p and q. Simple? :)
	if( !CalculateNZED( p, q ) )
	{	
		return false;
	}

	return true;
}

// p_p and p_q should be 2 different primes
bool RSA32::CalculateKeys( unsigned int p_p, unsigned int p_q )
{
	// Calculate n, z, e and d by using two primes: p and q. Simple? :)
	if( !CalculateNZED( p_p, p_q ) )
	{	
		return false;
	}

	return true;
}

// Calculate the public key by using n and z which already should be set.
bool RSA32::CalculatePublicKey( )
{
	// e is the encryption key( public key )
	e = 0;

	// Let's find e
	// e is odd and small.
	// !NOTE !NOTE !NOTE !NOTE 
	// What about the prime 2?
	for( unsigned int i = 3; i < z; i+=2 )
	{
		// Find the greatest common divisor. We want it to be 1. (coprime)
		if( EuclideanAlgorithm( z, i ) == 1 )
		{
			e = i;
			break;
		}
	}

	// Make sure we've found e, it should not be 0
	if( e == 0 )
	{
		return false;
	}

	return true;
}

// Calculate the private key by using e, n and z which already should be set.
bool RSA32::CalculatePrivateKey( )
{
	// d is the decryption key( private key ).
	// Do not let anyone see it except you.
	d = 0;

	// Use temporary 64 bit varaibles
	unsigned __int64 temp_d = 0;
	const unsigned __int64 temp_n = n;
	const unsigned __int64 temp_z = z;
	const unsigned __int64 temp_e = e;
	
	// Let's find d
	bool found_d = false;
	for( unsigned __int64 i = 0; i < temp_n; i++ )
	{
		// We've found d when ((i * z) + 1) / e is 0
		if( ( ( i * temp_z ) + 1 ) % temp_e == 0 )
		{
			temp_d = ( ( i * temp_z ) + 1 ) / temp_e;
			found_d = true;
			break;
		}
	}

	// Error check to make sure we've found d.
	if( !found_d )
	{
		return false;
	}

	// Set d.
	d = static_cast< unsigned int >( temp_d );
	return true;
}

// Clear all the varaibles.
void RSA32::Clear( )
{
	e = 0;
	d = 0;
	n = 0;
	z = 0;
}

// Cryptographic functions
unsigned int RSA32::Encrypt( unsigned int message )
{
	return PowMod( message, e, n );
}

unsigned int RSA32::Decrypt( unsigned int message )
{
	return PowMod( message, d, n );
}

// Set functions
void RSA32::SetE( unsigned int e )
{
	this->e = e;
}

void RSA32::SetD( unsigned int d )
{
	this->d = d;
}

void RSA32::SetN( unsigned int n )
{
	this->n = n;
}

void RSA32::SetZ( unsigned int z )
{
	this->z = z;
}

// Get functions
unsigned int RSA32::GetE( ) const
{
	return e;
}

unsigned int RSA32::GetD( ) const
{
	return d;
}

unsigned int RSA32::GetN( ) const
{
	return n;
}

unsigned int RSA32::GetZ( ) const
{
	return z;
}

// p and q should be 2 "large" primes
void RSA32::CalculateNZ( unsigned int p_p, unsigned p_q )
{
	n = p_p * p_q;
	z = ( p_p - 1 ) * ( p_q - 1 );
}

bool RSA32::CalculateNZED( unsigned int p_p, unsigned int p_q )
{
	// Calculate n and z
	CalculateNZ( p_p, p_q );

	// Calculate e
	if( !CalculatePublicKey( ) )
	{
		return false;
	}

	// Calculate D
	if( !CalculatePrivateKey( ) )
	{
		return false;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////////
// General function definitions

// Power modulus functions. 
unsigned int PowMod( unsigned int base, unsigned int exponent, unsigned int modulus )
{
	// Resource:
	// http://en.wikipedia.org/wiki/Modular_exponentiation

	if( base < 1 || exponent < 0 || modulus < 1 )
	{
		return 0;
	}

	// use 64 bit integers to make sure we're not getting out of range.
	unsigned __int64 result = 1;
	unsigned __int64 new_base = base;
	unsigned __int64 new_exponent = exponent;
	unsigned __int64 new_modulus = modulus;

	// Keep on looping until the exponent which is being divided
	// every single loop is larger than 0.
	while( new_exponent > 0 )
	{
		if( ( new_exponent % 2 ) == 1 )
		{
			result = ( result * new_base ) % new_modulus;
		}

		new_exponent = new_exponent >> 1;
		new_base = ( new_base * new_base ) % new_modulus;
	}

	// return the result as an unsigned int.
	return static_cast< unsigned int >( result );
}

unsigned int RandomNumber( unsigned int min, unsigned int max )
{
	return ( rand( ) % ( max - ( min - 1 ) ) ) + min;
}

// The min and max values is not the absolute min/max values
// The outcome from this function might give a highter prime than the max value.
unsigned int RandomPrime( unsigned int min, unsigned int max )
{
	unsigned int diff = 0;
	unsigned int number = RandomNumber( min, max );

	// Make sure the number is odd
	if( number % 2 == 0 )
	{
		number++;
	}

	// Swap min and max if min is larger than max
	if( min > max)
	{
		unsigned int temp_min = min;
		min = max;
		max = temp_min;
	}

	// Calculate the diff
	diff = max - min;

	// Find a prime by using the randomly generated number as a start number.
	for( unsigned int i = 0; i < diff; i++ )
	{
		if( IsPrime( number ) )
		{
			return number;
		}

		number += 2;
	}

	// We did not find any prime.
	return 0;
}

// Euclid's algorithm
//	a > b
unsigned int EuclideanAlgorithm( unsigned int a, unsigned int b )
{
	if( b >= a )
	{
		return a;
	}

	// The actual euclidean algorithm	
	unsigned int c = 0;
	while( b != 0 )
	{
		c = a % b;
		a = b;
		b = c;
	}

	return a;
}

bool IsPrime( unsigned int number )
{
	// Resource:
	// http://holmezideas.com/programming/optimization-techniques/fastest-algorithm-to-check-if-a-given-number-is-prime/

	if( number <= 1 )
	{
		return false;
	}
	else if( number == 2 )
	{
		return true;
	}
	else if( ( number % 2 ) == 0 )
	{
		return false;
	}
	else
	{
		float square_root = sqrt( static_cast< float >( number ) );

		// Let's loop sqrt( number ) times and check if the number isn't a prime
		for( unsigned int i = 3; i <= square_root; i+=2 )
		{
			if( ( number % i ) == 0 )
			{
				return false;
			}
		}
	}

	return true;
}