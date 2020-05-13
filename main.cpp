#include <iostream>
#include "IntegrityTree.h"
int main() {
    std::cout << "Hello, World!" << std::endl;
//    std::cout<< Block_id(250)<<std::endl;
//    std::cout<< Block_id(99)<<std::endl;
//    std::cout<< Block_id(100)<<std::endl;
//    std::cout<< Block_id(499)<<std::endl;
    init_memory();

   // print_memory();
//    print_memory();
//    std::cout<< memory[499];
//    std::cout<< memory[600];
    //getRoot();
//    char s[12];
//    generate_random(s,12);
//    print_trusted_memory();
    encrypt_memory();
//    print_memory();
//    std::cout<<s;
//    for(int i=HMAC_MAX_ADDR+1;i<MEMORY_SIZE;i++){
//        if(j > 0 && !(j % NONCE_SIZE)){
//            std::cout<<"\n";
//        }
//        std::cout<<memory[i];
//        j++;
//    }
//    std::cout<<"\n Keys are: \n";
//    for(int i=1;i<=8;i++){
//        std::cout<<" "<< trustedArea.get_key(i)<<"\n";
//    }
    unsigned char root[SHA_LENGTH_BYTES];
    getRoot(root);
//    std::vector<char*> res;
//    char c1[4]="asd";
//    char c2[5]="ahsd";
//    char c3[7]="axsd";
//    char c4[5]="zxsd";
//    res.push_back(c1);
//    res.push_back(c2);
//    res.push_back(c3);
//    res.push_back(c4);
//    for(int i=0;i<4;i++){
//        std::cout<<res[i]<<" ";
//    }
//    auto it=res.begin();
//    res.erase(it);
//    std::cout<<"\n\n";
//    for(int i=0;i<3;i++){
//        std::cout<<res[i]<<" ";
//    }
    trustedArea.update_root(root);
//    strncmptrustedArea.get_root()
//    unsigned char arr1[HMAC_SIZE]="Holla";
//    unsigned char arr2[HMAC_SIZE]="WeDemBoyz";
//    unsigned char arr3[2*HMAC_SIZE];
//    strncpy((char*)arr3,(char*)arr1,HMAC_SIZE);
//    strncat((char*)arr3,(char*)arr2,HMAC_SIZE);
//    unsigned char res[SHA_LENGTH_BYTES];
//    memset(res,0,SHA_LENGTH_BYTES);
//    SHA256(arr1,sizeof(arr1),res);
//    unsigned char res1[SHA_LENGTH_BYTES];
//    memset(res1,0,SHA_LENGTH_BYTES);
//    SHA256(arr1,sizeof(arr1),res1);

//    for(int i=0;i<SHA_LENGTH_BYTES;i++){
//        if(res[i]!=res1[i]){
//            std::cout<< "\n FUCK ME DEAD \n";
//        }
//    }
//    std::cout<<strncmp((char*)arr1,(char*)arr1,HMAC_SIZE)<<std::endl;
//    std::cout<<res<<std::endl;
//    std::cout<<res1;
    verify_integrity();
    trustedArea.get_number_of_tags();
    std::cout<<memory[BLOCK_MAX_ADDR+1]<<std::endl;
    update_memory(BLOCK_MAX_ADDR+1,'z');
    std::cout<<memory[BLOCK_MAX_ADDR+1]<<std::endl;
    trustedArea.get_number_of_tags();
    verify_integrity();
    update_memory(BLOCK_MAX_ADDR+1,'U');
    verify_integrity();


    //Root is 027
//    unsigned char adham[3]="aa";
//    unsigned char maher[3]="bb";
//    unsigned char result[6];
//    m_strncpy(result,adham,3);
//    m_strncat(result,3,maher,3);
//    std::cout<<result;
//    unsigned char hashed[SHA_LENGTH_BYTES];
//    SHA256(result,6,hashed);
//    std::cout<<strlen((char*)maher);
//    m_stdout(hashed,SHA_LENGTH_BYTES);
//    std::cout<<hashed[1];
    return 0;
}
