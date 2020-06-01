#include <iostream>
#include "IntegrityTree.h"
int main() {
    init_memory();
    encrypt_memory();
    unsigned char root[SHA_LENGTH_BYTES];
    unsigned char root2[SHA_LENGTH_BYTES];
    unsigned char root3[SHA_LENGTH_BYTES];
    getRoot(root);
    trustedArea.update_root(root);
    verify_integrity();
    unsigned char buffer[BLOCK_SIZE];
    unsigned char updated_buffer[BLOCK_SIZE];
    std::cout << read_block(4096,buffer) << std::endl;
   // m_stdout(buffer,4096);
    std::cout<<std::endl;
    unsigned char laban[32]="adham king of yogurt";
    write_block(4096,laban,32);
    getRoot(root2);
    std::cout<<"\nRead bytes are:"<< read_block(4096,updated_buffer)<<std::endl;
//    m_stdout(updated_buffer,4096);




    return 0;
}
