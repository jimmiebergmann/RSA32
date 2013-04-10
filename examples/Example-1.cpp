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
#include <time.h>
#include <iostream>

int main( )
{
	// Let's seed the rand function by using the time.
	srand( time( NULL ) );

	// Declare a RSA32 class and a message
	// that we want to encrypt and then finally decrypt.
	RSA32 rsa;
	const unsigned int message = 12345;

	// Randomly generate the keys
	rsa.RandomizeKeys( 0 );

	// [En][De]crypt the message
	unsigned int encrypted_message = rsa.Encrypt( message );
	unsigned int decrypted_message = rsa.Decrypt( encrypted_message );

	// Print the results
	std::cout << "Original message:\t" << message << std::endl;
	std::cout << "Encrypted message:\t" << encrypted_message << std::endl;
	std::cout << "Decrypted message:\t" << decrypted_message << std::endl << std::endl;
	std::cout << "Prime 1(P): " << rsa.GetP( ) << std::endl;
	std::cout << "Prime 1(Q): " << rsa.GetQ( ) << std::endl;
	std::cout << "Shared Key(N):  " << rsa.GetN( ) << std::endl;
	std::cout << "Phi N(Z):       " << rsa.GetZ( ) << std::endl;
	std::cout << "Public key(E):  " << rsa.GetE( ) << std::endl;
	std::cout << "Private key(D): " << rsa.GetD( ) << std::endl;

	// Wait for any input in order to close the program.
	std::cin.get( );
	return 0;
}