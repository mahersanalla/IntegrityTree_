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
//    std::cout<< memory[499];
//    std::cout<< memory[600];
    getRoot();
    return 0;
}