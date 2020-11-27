#ifndef INTEGRITYTREE_MAINMEMORY_H
#define INTEGRITYTREE_MAINMEMORY_H

#include <cmath>
#include "openSSLWraps.h"
#include <unordered_map>
#include <list>
#include "m_stdio.h"
#include <fstream>
#define BLOCK_MEMORY_SIZE 128*1024*1024
#define BLOCK_SIZE (4096)
#define NUM_OF_BLOCKS  (BLOCK_MEMORY_SIZE / BLOCK_SIZE)  //16
#define HMAC_SIZE 16
#define NONCE_SIZE 12
#define BLOCK_MAX_ADDR (BLOCK_SIZE*NUM_OF_BLOCKS - 1)   // 1500 is in range for last block..
#define HMAC_MAX_ADDR (BLOCK_MAX_ADDR + HMAC_SIZE*NUM_OF_BLOCKS)
#define SHA_LENGTH_BYTES 256 //probably 256 as sha256 says..
#define KEY_SIZE 32
#define MEMORY_SIZE (BLOCK_MEMORY_SIZE + 2*1024*1024 + (NONCE_SIZE+HMAC_SIZE) * NUM_OF_BLOCKS )
#define TREE_HEIGHT (int)(log2(NUM_OF_BLOCKS))
#include "TrustedArea.h"

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


int block_id(uint64_t addr){            //64 bit address
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    return (int)((addr)/((uint64_t)(BLOCK_SIZE)));
}
int hmac_id(uint64_t addr){
    if(addr<=BLOCK_MAX_ADDR || addr>HMAC_MAX_ADDR){
        return INVALID_HMAC_ADDR;
    }
    uint64_t offset = addr - BLOCK_MAX_ADDR;
    return (int)((offset)/((uint64_t)(HMAC_SIZE)));
}
uint64_t block_addr(int block_index){
    return block_index*BLOCK_SIZE;
}
// Input: Block address
// Output: HMAC address of the same block...
uint64_t hmac_addr(uint64_t addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    uint64_t _block_id=block_id(addr);
    return NUM_OF_BLOCKS*BLOCK_SIZE + _block_id * HMAC_SIZE;
}
uint64_t nonce_addr(uint64_t addr){
    if(addr<0 || addr>BLOCK_MAX_ADDR){
        return INVALID_BLOCK_ADDR;
    }
    uint64_t _block_id=block_id(addr);
    return NUM_OF_BLOCKS*BLOCK_SIZE + NUM_OF_BLOCKS * HMAC_SIZE + _block_id * NONCE_SIZE;
}

class MainMemory {
    unsigned char* memory;
    unsigned char* blocks_data;

public:
    MainMemory():memory(new unsigned char[MEMORY_SIZE]),
    blocks_data(new unsigned char[BLOCK_SIZE*NUM_OF_BLOCKS]){
        memset(memory,0,MEMORY_SIZE);
        memset(blocks_data,0,BLOCK_SIZE*NUM_OF_BLOCKS);
    }
    void init_memory(TrustedArea* trustedArea){
        memset(blocks_data,0,sizeof(memory));
        int i;
        int data = 'A';
        for(i=0 ; i <= BLOCK_MAX_ADDR;i++){
            if(i % BLOCK_SIZE == 0 && i>0){
                data++;
            }
            blocks_data[i] = data;
        }
        //Allocating empty root, Will be updated later
        unsigned char root[SHA_LENGTH_BYTES]="empty_root";
        trustedArea->allocate_in_trusted_memory(root,SHA_LENGTH_BYTES,false);
        for(i=0; i< NUM_OF_BLOCKS; i++){
            unsigned char* key=new unsigned char[KEY_SIZE];
            memset(key,0,sizeof(key));

            generate_random(key,KEY_SIZE);
            trustedArea->allocate_in_trusted_memory(key,KEY_SIZE,false);
            delete[] (key);
        }
        unsigned char nonce[NONCE_SIZE];
        int j=0;
        generate_random(nonce,NONCE_SIZE);
        for(i=HMAC_MAX_ADDR + 1 ; i < MEMORY_SIZE;i++){
            if(i % HMAC_SIZE == 0){
                j=0;
                generate_random(nonce,NONCE_SIZE);
            }
            memory[i] = nonce[j++];
        }

    }

    void encrypt_memory(TrustedArea* trustedArea){
        int j=0;

        int k=HMAC_MAX_ADDR + 1;
        int mem_index=0;
        unsigned char ciphertext[BLOCK_SIZE];
        unsigned char tag[16];
        unsigned char aad[256]="";
        for(int i=0;i<NUM_OF_BLOCKS;i++){
            unsigned char* plaintext=new unsigned char[BLOCK_SIZE];
            unsigned char* nonce=new unsigned char[NONCE_SIZE];
            unsigned char* key;
            memset(ciphertext,0,BLOCK_SIZE);
            memset(tag,0,HMAC_SIZE);
            m_strncpy(plaintext,(blocks_data + i*BLOCK_SIZE),BLOCK_SIZE);
            key=trustedArea->get_key(i+1);
            m_strncpy(nonce,(memory + (k + (i*NONCE_SIZE))),NONCE_SIZE);
            int cipher_len=gcm_encrypt(plaintext,BLOCK_SIZE,aad,0,key,nonce,NONCE_SIZE,ciphertext,tag);
            m_strncpy((memory+i*BLOCK_SIZE),ciphertext,BLOCK_SIZE);
            m_strncpy((memory+ BLOCK_MAX_ADDR+1 + i*HMAC_SIZE),tag,HMAC_SIZE);
            delete[] plaintext;
            delete[] nonce;
        }
    }


    ReturnValue memread(uint64_t addr,unsigned char* buf,int size){
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
    ReturnValue memwrite(uint64_t addr,unsigned char* buf,int size){
        if(addr < 0 || addr > MEMORY_SIZE){
            return INVALID_ADDR;
        }
        int i,j=0;
        for(i = (int)addr; i < addr + size ; i++){
            memory[i]=buf[j++];
        }
        return SUCCESS;
    }

    void update_memory(int addr,char value){
        memory[addr]=value;
    }

    void print_memory(){
        int i;
        for( i = 0; i < MEMORY_SIZE; i++){
            std::cout<< " " << memory[i] << " ";
        }
    }
    void print_blocks_data(){
        int i;
        for( i = 0; i < BLOCK_SIZE*NUM_OF_BLOCKS; i++){
            std::cout<< " " << blocks_data[i] << " ";
        }
        std::cout<<std::endl;
    }
    unsigned char* getMemoryAddress(uint64_t addr){
        return memory+addr;
    }
    unsigned char* getMemoryPointer(){
        return memory;
    }


    ~MainMemory(){
        delete[] memory;
        delete[] blocks_data;
    }



};

#endif //INTEGRITYTREE_MAINMEMORY_H
