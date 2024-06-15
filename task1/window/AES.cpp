
#include "AES.h"
#include <chrono>

string input()
{
    int choose;
    string input;
    cout<<"Please choose your input\n";
    cout<<"1-Input from keyboard\n";
    cout<<"2-Input from File\n";
    cout<<"Your choice 1 or 2: ";
    cin>>choose;
    switch (choose)
    {
        case 1:
        {
            cout<<"Your input: ";
            cin.ignore();
            getline(cin,input);
            break;
        }
        case 2:
        {
            string Filename;
            cout<<"Your Filename: ";
            cin>>Filename;
            FileSource(Filename.data(),true,new StringSink(input));
            break;
        }
        default: break;
    }
    return input;
}

void Genkey(int choose)
{
    switch(choose)
    {
        case 2:
        {
            string key,iv;
            cout<<"Enter your Key: ";
            cin>>key;
            cout<<"Enter yout IV: ";
            cin>>iv;
            StringSource(key,true, new HexEncoder(new ArraySink(keys.key,sizeof(keys.key))));
            StringSource(iv,true, new HexEncoder(new ArraySink(keys.iv,sizeof(keys.iv))));
            break;
        }
        case 3:
        {
            string KeyFilename,IVFilename;
            cout<<"Enter your KeyFilename: ";
            cin>>KeyFilename;
            cout<<"Enter Your IVFilename: ";
            cin>>IVFilename;
            FileSource(KeyFilename.data(),true, new HexEncoder(new ArraySink(keys.key,sizeof(keys.key))));
            FileSource(IVFilename.data(),true,new HexEncoder(new ArraySink(keys.iv,sizeof(keys.iv))));
            break;
        }
        default: break;
    }
}

void SaveFile(string input)
{
    string FileName;
    cout << "Enter FileName:";
    cin.ignore();
    cin >> FileName;
    StringSource(input,true,new FileSink(FileName.data()));
}

void cipheroutput(string cipher, int output)
{
    switch(output)
    {
        case 1:
        {
           cout<<"Ciphertext: "<< cipher <<endl;
           return ;
           break;

        }
        case 2:
        {
           SaveFile(cipher);
           break;
        }
        default: break;
    }
}

int main(int argc, char* argv[])
{
    #ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
    #endif
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
    string plain;
    int keychoose,mode;
    string encoded, recovered;
    plain = input();
    cout << "Plaintext: " << plain << endl;
    cout<<"Please choose your key options \n";
    cout<<"1-Key random from prng\n";
    cout<<"2-Key from keyboard\n";
    cout<<"3-Key from your file\n";
    cout<<"Your choice is : ";
    cin>>keychoose;
    switch (keychoose)
    {
        case 1: // key random
        {
            AutoSeededRandomPool prng;
            prng.GenerateBlock(keys.key, sizeof(keys.key));
            string encodedKey;
            StringSource(keys.key, sizeof(keys.key), true, new HexEncoder(new StringSink(encodedKey)));        
            cout << "Generated Key: " << encodedKey << endl;
            string encodedIV;
            prng.GenerateBlock(keys.iv, sizeof(keys.iv));
            StringSource(keys.iv, sizeof(keys.iv), true, new HexEncoder(new StringSink(encodedIV)));      
            cout << "Generated IV: " << encodedIV << endl;
            break;
        }
        case 2: // nhap key from keyboard
        {
            Genkey(2);
            break;
        }
        case 3: // nhap key from filename
        {
            Genkey(3);
            break;
        }
        default:
        {
            cout<<"Error:";
            return 0;
        }
    }
    while(true)
    {
        // Encrypt or decrypt 
        int select;
        cout<<"Would you like to encrypt or decrypt message:\n";
        cout<<"1-Encrypt;\n";
        cout<<"2-Decrypt;\n";
        cout<<"Your choice is: ";
        cin>>select;
        switch(select) 
        {
            case 1: // Encrypt du lieu
            {
                cout<<"Please choose mode to encrypt\n";
                cout<<"1.ECB, 2.CBC, 3.OFB, 4.CFB, 5.CTR, 6.XTS, 7.CCM, 8.GCM\n";
                cout<<"Your choice is: ";
                cin>>mode;
                int out;
                cout<<"Save output on :\n";
                cout<<"1- On screen\n";
                cout<<"2- On file\n";
                cout<<"Please choose a number(1-2):";
                cin>>out;
                switch (mode)
                {
                    case 1: // ECB encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher = EncyptECB(plain); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        cipheroutput(encoded,out);
                        break;
                    }
                    case 2: // CBC encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher = EncryptCBC(plain); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        cipheroutput(encoded,out);
                        break;
                    }
                    case 3: // OFB encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher = EncryptOFB(plain); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        cipheroutput(encoded,out);
                        break;
                    }
                    case 4: // CFB encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher=EncryptCFB(plain); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        cipheroutput(encoded,out);
                        break;
                    }
                    case 5: // CTR encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher = EncryptCTR(plain); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        cipheroutput(encoded,out);
                        break;
                    }
                    case 6: // XTS encrypt
                    {
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher = EncryptXTS(plain); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        cipheroutput(encoded,out);
                        break;
                    }
                    case 7: // CCM encrypt
                    {       
                        string cipher;                 
                        auto start = std::chrono::high_resolution_clock::now();
                        CryptoPP::byte truncatedIV[13];
	                    memcpy(truncatedIV, keys.iv, 13);
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher = EncryptCCM(plain, truncatedIV); 
                        }
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(encoded,out);
                        break;
                        
                    }
                    case 8: // GCM encrypt
                    {
                        string AAD;
                        cout << "Enter Additional Authenticated Data(AAD): "; 
                        cin >> AAD;
                        
                        string cipher;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            cipher=EncryptGCM(plain,AAD); 
                        }
                        string encoded;
                        StringSource(cipher, true, new Base64Encoder(new StringSink(encoded), true));
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for encryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(encoded,out);
                        break;
                    }
                    default:
                    {
                        cout<<"Invalid option";
                        return 0;
                    }
                }
                break;
            }
            case 2: // Decrypt du lieu
            {
                cout<<"Please choose mode to encrypt\n";
                cout<<"1.ECB, 2.CBC, 3.OFB, 4.CFB, 5.CTR, 6.XTS, 7.CCM, 8.GCM\n";
                cout<<"Your choice is: ";
                cin>>mode;
                // Nhap ciphertext
                string cipher,plain;
                plain=input();
                StringSource(plain, true, new Base64Decoder(new StringSink(cipher)));
                int out;
                cout<< "How do you want to display output:\n"
                << "1.Display in screen\n"
                << "2.Write on file\n"
                << "Please choose a number(1-2): ";
                cin>>out;
                switch(mode)
                {
                    case 1: // ECB 
                    {
                        string plain;
                        auto start=std::chrono::high_resolution_clock::now();
                        for (int i=0;i<10000;++i) 
                        {
                            plain=DecryptECB(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(plain,out);
                        break;
                    }
                    case 2: // CBC 
                    {
                        string plain;
                        auto start=std::chrono::high_resolution_clock::now();
                        for (int i=0;i<10000;++i) 
                        {
                            plain=DecryptCBC(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(plain,out);
                        break;                 
                    }
                    case 3: // OFB 
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            plain=DecryptOFB(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(plain,out);
                        break;
                    }
                    case 4: // CFB 
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            plain=DecryptCFB(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(plain,out);
                        break;
                    }
                    case 5: // CTR 
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            plain=DecryptCTR(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(plain,out);
                        break;
                    }
                    case 6: // XTS 
                    {
                        string plain;
                        auto start = std::chrono::high_resolution_clock::now();
                        for (int i = 0; i < 10000; ++i) 
                        {
                            plain=DecryptXTS(cipher); 
                        }
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << endl;
                        cipheroutput(plain,out);
                        break;
                    }
                    case 7: // CCM 
                    {
                        string decoded;
                        StringSource(cipher, true, new HexDecoder(new StringSink(decoded)));
                        auto BeginTime=std::chrono::high_resolution_clock::now();
                        for (int i = 1; i <=10000; i++)
                        {
                            plain=DecrypCCM(decoded);
                        } 
                        auto EndTime = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - BeginTime).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << endl;
                        cipheroutput(decoded,out);
                        break;
                    }
                    case 8: // GCM 
                    {
                        string AAD;
                        cout<<"Additional Authenticated Data(AAD): ";
                        cin>>AAD;
                        auto start = std::chrono::high_resolution_clock::now();
                        pair<string, string> output;
                        for (int i = 0; i < 10000; ++i) 
                        {
                            output=DecryptGCM(cipher, AAD);
                        }
                        string radata = output.first, rpdata = output.second;
                        auto end = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                        double averageTime = static_cast<double>(duration) / 10000.0;
                        std::cout << "Average time for decryption over 10000 rounds: " << averageTime << " ms" << std::endl;
                        cipheroutput(rpdata,out);
                        cout << "Recovered adata: " << radata << endl;
                        break;
                    }
                    default:
                    {
                        cout << "Invalid option";
                        return 0;
                    }
                }
                return 0;
            }
            default:
            {
                cout << "Invalid input\n";
                return 0;
            }    
        }
    }
    return 0;
}