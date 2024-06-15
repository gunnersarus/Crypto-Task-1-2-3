//C internal library 
#include <iostream>
using std::endl;
#include <string>
using std::string;
using std::string;
#include <cstdlib>
using std::exit;
#include <fstream>
#include <utility>
#include "assert.h"
//Cryptopp Librari
#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes


#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;
#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;

// convert string
// Hex <---> Binary
#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Base64 <---> Binary
#include "include/cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

// Block cipher
#include "include/cryptopp/des.h"
using CryptoPP::DES;
#include "include/cryptopp/aes.h"
using CryptoPP::AES;

//Mode of operations
#include "include/cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
#include "include/cryptopp/xts.h"
using CryptoPP::XTS;
#include "include/cryptopp/ccm.h"
using CryptoPP::CCM;
#include "include/cryptopp/gcm.h"
using CryptoPP::GCM;
//Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison


/* Set utf8 support for windows*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#else
#endif
/* Convert string <--> utf8*/ 
#include <locale>
#include <codecvt>
using  std::codecvt_utf8;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;
using namespace CryptoPP;

struct AESKeys{
    CryptoPP::byte key[AES::MAX_KEYLENGTH];
    CryptoPP::byte iv[AES::BLOCKSIZE];
};

AESKeys keys;

string EncyptECB(string &plain)
{
    string cipher;
    ECB_Mode< AES >::Encryption e;
	e.SetKey(keys.key, AES::MAX_KEYLENGTH);
	StringSource(plain, true, new StreamTransformationFilter(e,new StringSink(cipher))); 
    return cipher;
}

string EncryptCBC(string &plain)
{
    string cipher;
    CBC_Mode< AES >::Encryption e;
    e.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource s(plain, true,  new StreamTransformationFilter(e, new StringSink(cipher))); 
    return cipher;
}

string EncryptOFB(string &plain)
{
    string cipher;
    OFB_Mode< AES >::Encryption e;
    e.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource(plain,true,new StreamTransformationFilter(e,new StringSink(cipher))); 
    return cipher;
}

string EncryptCFB(string &plain)
{
    string cipher;

    CFB_Mode< AES >::Encryption e;
    e.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource(plain, true,new StreamTransformationFilter(e,new StringSink(cipher))); 
    return cipher;
}

string EncryptCTR(string &plain)
{
    string cipher;
    CTR_Mode< AES >::Encryption e;
    e.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    return cipher;
}

string EncryptXTS(string &plain)
{
    string cipher;
    XTS_Mode< AES >::Encryption enc;
    enc.SetKeyWithIV( keys.key, sizeof(keys.key), keys.iv );
    StringSource ss( plain, true, new StreamTransformationFilter( enc,new StringSink( cipher ),StreamTransformationFilter::NO_PADDING)); 
    return cipher;
}

string EncryptCCM(string &pdata, CryptoPP::byte* truncatedIV)
{
	string cipher;
	const int TAG_SIZE = 8;
	CCM< AES, TAG_SIZE >::Encryption e;
    e.SetKeyWithIV( keys.iv, sizeof(keys.key), truncatedIV, sizeof(truncatedIV));
    e.SpecifyDataLengths( 0, pdata.size(), 0);
    StringSource( pdata, true, new AuthenticatedEncryptionFilter( e,new StringSink(cipher)));
    return cipher;
}

string EncryptGCM(string pdata, string adata)
{
	const int TAG_SIZE = 16;
	string cipher;
    GCM< AES >::Encryption e;
    e.SetKeyWithIV( keys.key, sizeof(keys.key), keys.iv, sizeof(keys.iv) );
    AuthenticatedEncryptionFilter ef( e,new StringSink( cipher ), false, TAG_SIZE ); 
    ef.ChannelPut( "AAD", (const CryptoPP::byte*)adata.data(), adata.size() );
    ef.ChannelMessageEnd("AAD");
    ef.ChannelPut( "", (const CryptoPP::byte*)pdata.data(), pdata.size() );
    ef.ChannelMessageEnd("");
    return cipher;
}


string DecryptECB(string &cipher)
{
    string plain;
    ECB_Mode< AES >::Decryption d;
    d.SetKey(keys.key, sizeof(keys.key));
    StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain) )); 
    return plain;
}

string DecryptCBC(string &cipher)
{
    string recovered;

    CBC_Mode< AES >::Decryption d;
    d.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource s(cipher, true, new StreamTransformationFilter(d,new StringSink(recovered))); 
    return recovered;
}

string DecryptOFB(string &ciphertext)
{
    string recovered;
    OFB_Mode< AES >::Decryption d;
    d.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource s(ciphertext, true, new StreamTransformationFilter(d,new StringSink(recovered))); 
    return recovered;
}

string DecryptCFB(string &ciphertext)
{
    string recovered;
    CFB_Mode< AES >::Decryption d;
    d.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource s(ciphertext, true,new StreamTransformationFilter(d,new StringSink(recovered))); 
    return recovered;
}

string DecryptCTR(string &ciphertext)
{
    string recovered;

    CTR_Mode< AES >::Decryption d;
    d.SetKeyWithIV(keys.key, sizeof(keys.key), keys.iv);
    StringSource s(ciphertext, true, new StreamTransformationFilter(d,new StringSink(recovered)) ); 
    return recovered;
}

string DecryptXTS(string &ciphertext)
{
    string recovered;
    XTS_Mode< AES >::Decryption dec;
    dec.SetKeyWithIV( keys.key, sizeof(keys.key), keys.iv );
    StringSource ss( ciphertext, true, new StreamTransformationFilter(dec,new StringSink(recovered),StreamTransformationFilter::NO_PADDING) );   
	return recovered;
}

string DecrypCCM(string cipher)
{
  string recovered;
  CryptoPP::byte newIV[AES::BLOCKSIZE];
  for (int i = 0; i < AES::BLOCKSIZE; i++) 
  {
    newIV[i] = keys.iv[i];
  }
  CCM<AES, 8>::Decryption d;
  d.SetKeyWithIV(keys.key, sizeof(keys.key), newIV);
  size_t cipherTextLength = cipher.size() - 8;
  size_t macLength = 8;
  d.SpecifyDataLengths(0, cipherTextLength, 0);

  AuthenticatedDecryptionFilter df(d,new StringSink(recovered),AuthenticatedDecryptionFilter::DEFAULT_FLAGS,macLength);
  StringSource s(cipher, true,new Redirector(df));
  return recovered;
}

pair<string, string> DecryptGCM(string &cipher, string &adata)
{
	string radata, rpdata;
	const int TAG_SIZE = 16;
	try
    {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV( keys.key, sizeof(keys.key), keys.iv, sizeof(keys.iv) );
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );
        assert( cipher.size() == enc.size() + mac.size() );
        assert( TAG_SIZE == mac.size() );
        radata = adata;     
        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        df.ChannelPut( "", (const CryptoPP::byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const CryptoPP::byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const CryptoPP::byte*)enc.data(), enc.size() );               
        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );
        string retrieved;
        size_t n = (size_t)-1;
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if(n>0) 
        {
             df.Get( (CryptoPP::byte*)retrieved.data(), n ); 
        }
        rpdata = retrieved;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    return make_pair(radata,rpdata);
}


