//
// Created by root on 4/30/20.
//
#ifndef INTEGRITYTREE_INTEGRITYTREE_H
#define INTEGRITYTREE_INTEGRITYTREE_H

#include "openSSLWraps.h"
#include "MainMemory.h"
#include "TrustedArea.h"
#include "m_stdio.h"
#include <cassert>
#include <fstream>
using namespace std;

//
//MainMemory mainMemory;
//TrustedArea trustedArea;


void decToBinary(int n,int binaryNum[])
{
    // array to store binary number
    // counter for binary array
    for(int i=0;i<32;i++){
        binaryNum[i]=0;
    }
    int i = 0;
    while (n > 0) {

        // storing remainder in binary array
        binaryNum[i] = n % 2;
        n = n / 2;
        i++;
    }
}

ReturnValue getRoot(MainMemory* mainMemory,TrustedArea* trustedArea,unsigned char* result){
    int j=1;
    for(int i = BLOCK_MAX_ADDR + 1; i<= HMAC_MAX_ADDR-2*HMAC_SIZE+1; i+= 2*HMAC_SIZE) {
        unsigned char buf1[HMAC_SIZE], buf2[HMAC_SIZE];
        memset(buf1,0,HMAC_SIZE);
        memset(buf2,0,HMAC_SIZE);
        mainMemory->memread(i, buf1, HMAC_SIZE);
        mainMemory->memread(i + HMAC_SIZE, buf2, HMAC_SIZE);
        unsigned char tmp[2 * HMAC_SIZE];
        memset(tmp,0,2*HMAC_SIZE);
        m_strncpy(tmp,buf1, HMAC_SIZE);
        m_strncat(tmp,HMAC_SIZE,buf2, HMAC_SIZE);
        unsigned char hashed_data[SHA_LENGTH_BYTES];
        memset(hashed_data,0,SHA_LENGTH_BYTES);
        SHA256(tmp,sizeof(tmp), hashed_data);
        trustedArea->allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);

    }
    int n=0; //Que eso?
    while((n=trustedArea->get_number_of_tags())>1){
        for(int i=0; i<= n-2; i+=2){
            unsigned char sha2[2*SHA_LENGTH_BYTES];
            memset(sha2,0,2*SHA_LENGTH_BYTES);
            m_strncpy(sha2, trustedArea->get_tag(),SHA_LENGTH_BYTES);
            trustedArea->delete_tag();
            m_strncat(sha2,SHA_LENGTH_BYTES,trustedArea->get_tag(),SHA_LENGTH_BYTES);
            trustedArea->delete_tag();
            unsigned char hashed_data[SHA_LENGTH_BYTES];
            memset(hashed_data,0,SHA_LENGTH_BYTES);
            SHA256(sha2,sizeof(sha2), hashed_data);
            trustedArea->allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);
        }
    }

  //  std::cout<<"\nTHE ROOTT ISSSS : \n\n\n\n";
  //  std::cout<<trustedArea.get_tag();

    m_strncpy(result,trustedArea->get_tag(),SHA_LENGTH_BYTES);
    trustedArea->delete_tag();

    return SUCCESS;

}



bool verify_integrity(MainMemory* mainMemory,TrustedArea* trustedArea){
    unsigned char curr_root[SHA_LENGTH_BYTES];
    memset(curr_root,0,SHA_LENGTH_BYTES);
    getRoot(mainMemory,trustedArea,curr_root);
    if(!m_strncmp(curr_root,(trustedArea->get_root()),SHA_LENGTH_BYTES)){
//        std::cout<<"\n\nTHE TREE IS VALID---\n";
        return true;
    }
//    std::cout<<"THE TREE IS FUCKED:( LEAVE AND THROW THE PC NOWWWW!\n\n\n\n";
    return false;
}
// Binary index of block 001 , status Invalid/Valid , Data
void write_to_log(int binaryIndex[],int status, unsigned char* data){
    ofstream mylog("log.txt",std::ofstream::app);
    mylog << status <<" ";
    for(int i=0;i<3;i++){
        mylog<<binaryIndex[i];
    }

    mylog<<" "<< data << std::endl;
    mylog.close();
}
void erase_log(){
    std::ofstream ofs;
    ofs.open("log.txt", std::ofstream::out | std::ofstream::trunc);
    ofs.close();
}

int read_block_by_addr(MainMemory* mainMemory,TrustedArea* trustedArea,uint64_t addr,unsigned char* buf){
    int index = block_id(addr);
    if(!verify_integrity(mainMemory,trustedArea)){
        return -1;
    }
    unsigned char* tmp_buf;
    unsigned char* nonce;
    unsigned char* hmac;
    unsigned char* key;
    tmp_buf=mainMemory->getMemoryAddress(index*BLOCK_SIZE);
    uint64_t nonce_address=nonce_addr(addr);
    uint64_t hmac_address=hmac_addr(addr);
    key=trustedArea->get_key(index+1);  //Found key
    nonce=mainMemory->getMemoryAddress(nonce_address);
    hmac=mainMemory->getMemoryAddress(hmac_address);
    unsigned char aad[256]="";
    int read_size = gcm_decrypt(tmp_buf,BLOCK_SIZE,aad,256,hmac,key,nonce,NONCE_SIZE,buf);

    return read_size;                          // How many bytes we actually decrypted and read
}
int read_block(MainMemory* mainMemory,TrustedArea* trustedArea,int block_index,unsigned char* buf){
    uint64_t addr=block_index*BLOCK_SIZE;
    return read_block_by_addr(mainMemory,trustedArea,addr,buf);
}
int write_block(MainMemory* mainMemory,TrustedArea* trustedArea, int block_index,unsigned char* buf,int size_to_write){
    if(!verify_integrity(mainMemory,trustedArea)){
        return -1;                  //ERROR
    }
    int binaryNum[32];
    decToBinary(block_index,binaryNum);
    write_to_log(binaryNum,0,buf);
    uint64_t addr= block_index*BLOCK_SIZE;
    uint64_t nonce_address=nonce_addr(addr);
    uint64_t hmac_address=hmac_addr(addr);
    unsigned char ciphertext[BLOCK_SIZE];
    unsigned char new_tag[16];
    unsigned char new_aad[256]="";
    unsigned char* new_key=new unsigned char[KEY_SIZE];
    unsigned char* new_nonce=new unsigned char[NONCE_SIZE];
    memset(ciphertext,0,BLOCK_SIZE);
    memset(new_tag,0,HMAC_SIZE);
    memset(new_key,0,KEY_SIZE);
    generate_random(new_nonce,NONCE_SIZE);
    generate_random(new_key,KEY_SIZE);
    trustedArea->update_key(block_index+1, new_key);
    unsigned char *stam_key = trustedArea->get_key(block_index+1);
    gcm_encrypt(buf,BLOCK_SIZE,new_aad,256,stam_key,new_nonce,NONCE_SIZE,ciphertext,new_tag);
    mainMemory->memwrite(block_index*BLOCK_SIZE,ciphertext,BLOCK_SIZE);
    mainMemory->memwrite(hmac_address,new_tag,HMAC_SIZE);
    mainMemory->memwrite(nonce_address,new_nonce,NONCE_SIZE);
//    trustedArea->update_key(index+1,new_key);
    unsigned char new_root[SHA_LENGTH_BYTES];
    getRoot(mainMemory,trustedArea,new_root);
    trustedArea->update_root(new_root);
    erase_log();
    delete[] new_key;
    delete[] new_nonce;
    return 0;
}

void printToFile(MainMemory* mainMemory,TrustedArea* trustedArea){
    std::ofstream ofs;
    ofs.open("memory.txt", std::ofstream::out | std::ofstream::trunc);
    ofs.close();
    ofstream memFile("memory.txt",std::ofstream::app);
    memFile << "Printing Memory : \n";
    for(int i=0;i<NUM_OF_BLOCKS ;i++){
        unsigned char* data=new unsigned char[BLOCK_SIZE];
        read_block(mainMemory,trustedArea,i,data);
        memFile << data << "\n";
        delete[] data;
    }
//    memFile<< " " << std::endl;
    memFile.close();
}


#endif //INTEGRITYTREE_INTEGRITYTREE_H