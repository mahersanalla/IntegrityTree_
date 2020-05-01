//
// Created by root on 4/30/20.
//
#ifndef INTEGRITYTREE_INTEGRITYTREE_H
#define INTEGRITYTREE_INTEGRITYTREE_H

#include "openSSLWraps.h"
#include <queue>
#include <list>
#define BLOCK_SIZE 100
#define NUM_OF_BLOCKS 5
#define HMAC_SIZE 100
#define NONCE_SIZE 100
#define BLOCK_MAX_ADDR 499   // 1500 is in range for last block..
#define HMAC_MAX_ADDR 999
#define SHA_LENGTH_BYTES 512
#define MEMORY_SIZE 1500
typedef enum{
    INVALID_BLOCK_ADDR,
    INVALID_HMAC_ADDR,
    INVALID_NONCE_ADDR,
    TAMPERED_TREE,
    NO_RIGHT_NEIGHBOR,
    NO_LEFT_NEIGHBOR,
    INVALID_ADDR,
    SUCCESS
}ReturnValue;
unsigned char memory[MEMORY_SIZE];
void init_memory(){
  //  char* memory = new char[MEMORY_SIZE];
    memset(memory,0,sizeof(memory));
    int i;
    int data = 'a'-1;
    for(i=0 ; i <= BLOCK_MAX_ADDR;i++){
        if(i % BLOCK_SIZE == 0){
            data++;
        }
        memory[i] = data;
    }
    int hmac_data = 80;
    for(i=BLOCK_MAX_ADDR + 1 ; i <= HMAC_MAX_ADDR;i++){
        if(i % HMAC_SIZE == 0){
            hmac_data++;
        }
        memory[i] = hmac_data;
    }
    //return memory;
}
void print_memory(){
    int i;
    std::cout<< " MEMORY (NON-VOLATILE)\n"<<memory;
//    for( i = 0; i < MEMORY_SIZE; i++){
//        if(i % 100 == 0){
//            std::cout << "\n";
//        }
//        std::cout<< " " << memory[i] << " ";
//    }
}
ReturnValue memread(double addr,unsigned char* buf,int size){
    //char* tmp;
    if(addr < 0 || addr > MEMORY_SIZE){
        return INVALID_ADDR;
    }
    int i,j=0;
    for(i = (int)addr; i < addr + size ; i++){
        buf[j++]=memory[i];
    }
    return SUCCESS;
}
double addrToDouble(unsigned char* addr){
    double res =  strtod((char*)addr,NULL);
    return res;
}
int Block_id(double addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    return (int)((addr)/((double)(BLOCK_SIZE)));
}
int Hmac_id(double addr){
    if(addr<=BLOCK_MAX_ADDR || addr>HMAC_MAX_ADDR){
        return INVALID_HMAC_ADDR;
    }
    double offset = addr - BLOCK_MAX_ADDR;
    return (int)((offset)/((double)(HMAC_SIZE)));
}
// Input: Block address
// Output: HMAC address of the same block...
double Hmac_addr(double addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    double _block_id=Block_id(addr);
    return NUM_OF_BLOCKS*BLOCK_SIZE + _block_id * HMAC_SIZE;
}
double Nonce_addr(double addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    double _block_id=Block_id(addr);
    return NUM_OF_BLOCKS*BLOCK_SIZE + NUM_OF_BLOCKS * HMAC_SIZE + _block_id * NONCE_SIZE;
}
ReturnValue getRightNeighbor(double hmac_addr,double* right_neighbour){
    double _hmac_id=Hmac_id(hmac_addr);
    if(_hmac_id<0){
        return INVALID_HMAC_ADDR;
    }
    if(_hmac_id == NUM_OF_BLOCKS - 1){
        return NO_RIGHT_NEIGHBOR;
    }
    *right_neighbour = Hmac_addr(_hmac_id + 1);
    return SUCCESS;
}
ReturnValue getLeftNeighbour(double hmac,double* left_neighbour){
    double _hmac_id=Hmac_id(hmac);
    if(_hmac_id<0){
        return INVALID_HMAC_ADDR;
    }
    if(_hmac_id == 0){
        return NO_LEFT_NEIGHBOR;
    }
    *left_neighbour = Hmac_addr(_hmac_id - 1);
    return SUCCESS;
}
//Input: hmac of left son + hmac of right son + pointer to allocated char buffer with SHA_LENGTH_BYTES
//That will contain the result of the hash at the end
ReturnValue getParentHash(unsigned char* hmac1, unsigned char* hmac2,unsigned char** parent_hash){
    unsigned char* tmp_buf=new unsigned char[strlen((char*)hmac1)+strlen((char*)hmac2)];
    strcpy((char*)tmp_buf,(const  char*)hmac1); // Now tmp_buf holds hmac1 data & has space for hmac2 data
    strcat((char*)tmp_buf,(const char*)hmac2);
    unsigned char* hashed_data=new unsigned char[SHA_LENGTH_BYTES];
    SHA256(tmp_buf,sizeof(tmp_buf),hashed_data);
    strcpy((char*)(*parent_hash),(char*)hashed_data);
    delete[] tmp_buf;
    delete[] hashed_data;
    return SUCCESS;
}

// This function gets a hmac address, and calculates the root of the tree starting from the given hmac.
/*ReturnValue traverseTree(double hmac_addr){
    double hmac_id = Hmac_id(hmac_addr);
    if(hmac_id < 0){
        return INVALID_HMAC_ADDR;
    }
    double curr_addr = BLOCK_MAX_ADDR + 1;
    char hmac1_data[HMAC_SIZE];
    char hmac2_data[HMAC_SIZE];
    double neighbor_addr;
    queue<char*> level;
    for(curr_addr ; curr_addr <= HMAC_MAX_ADDR ; curr_addr+=HMAC_SIZE){
        memread(curr_addr,hmac1_data,HMAC_SIZE);
        level.push((char*)hmac1_data);
        memset(hmac1_data,0,sizeof(hmac1_data));
    }


}*/

ReturnValue getRoot(){
    std::vector<unsigned char*> nodes;
    std::vector<unsigned char*> leaves;
    std::list<unsigned char*> allocs;
    unsigned char* hashed_data;
//    char buf[HMAC_SIZE];
    /*char* tmp_buf=new char[HMAC_SIZE];*/
    for(int i = BLOCK_MAX_ADDR + 1 ;i <= HMAC_MAX_ADDR; i += HMAC_SIZE){
        unsigned char* buf=new unsigned char[HMAC_SIZE];
        memset(buf,0,sizeof(buf));
        allocs.push_back(buf);
        memread(i,buf,HMAC_SIZE);
        nodes.push_back(buf);
    }
    std::cout<<nodes[2];
    leaves=nodes;
    nodes.clear();
    while (leaves.size() != 1) {
        for(int i = 0; i <= leaves.size() - 2 ; i+=2){
            unsigned char* tmp_buf=new unsigned char[strlen((char*)leaves[i])+strlen((char*)leaves[i+1])+1];
            strcpy((char*)tmp_buf,(const  char*)leaves[i]); // Now tmp_buf holds leaves[i] data & has space for leaves[i+1]
            strcat((char*)tmp_buf,(const char*)leaves[i+1]);
            unsigned char* hashed_data=new unsigned char[SHA_LENGTH_BYTES];
            allocs.push_back(tmp_buf);
            allocs.push_back(hashed_data);
            SHA256(tmp_buf,sizeof(tmp_buf),hashed_data);
            nodes.push_back(hashed_data);
//            delete(tmp_buf);
//            delete(hashed_data);
        }
        leaves = nodes; //copy c'tor of Node!
        nodes.clear();
    }
    //FIXME: EMPTY THE LIST (DELETE)
    std::cout<< "\n \nThe Root is:"<<leaves.front();
    // HERE WE COMPARE THE ROOT WITH THE TRUSTED AREA ROOT

//   compare root vs leaves[0]

    //FREE ALL THE ALLOCATED SPACE
    auto it=allocs.begin();
    auto tmp=it;
    unsigned long size=allocs.size();
    while(size--){
        tmp=it;
        it++;
        delete(*tmp);
    }
    return SUCCESS;
}




#endif //INTEGRITYTREE_INTEGRITYTREE_H
