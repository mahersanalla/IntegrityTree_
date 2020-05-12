#include <iostream>
#include "IntegrityTree.h"
int main() {
    std::cout << "Hello, World!" << std::endl;
//    std::cout<< Block_id(250)<<std::endl;
//    std::cout<< Block_id(99)<<std::endl;
//    std::cout<< Block_id(100)<<std::endl;
//    std::cout<< Block_id(499)<<std::endl;
      init_memory();
//    print_memory();
//    print_memory();
//    std::cout<< memory[499];
//    std::cout<< memory[600];
    //getRoot();
//    char s[12];
//    generate_random(s,12);
//    print_trusted_memory();
//      encrypt_memory();
//      print_memory();
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
//    getRoot();
    std::vector<char*> res;
    char c1[4]="asd";
    char c2[5]="ahsd";
    char c3[7]="axsd";
    char c4[5]="zxsd";
    res.push_back(c1);
    res.push_back(c2);
    res.push_back(c3);
    res.push_back(c4);
    for(int i=0;i<4;i++){
        std::cout<<res[i]<<" ";
    }
    auto it=res.begin();
    res.erase(it);
    std::cout<<"\n\n";
    for(int i=0;i<3;i++){
        std::cout<<res[i]<<" ";
    }
    return 0;
}
