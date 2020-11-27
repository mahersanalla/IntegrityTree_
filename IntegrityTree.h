//
// Created by root on 4/30/20.
//
#ifndef INTEGRITYTREE_INTEGRITYTREE_H
#define INTEGRITYTREE_INTEGRITYTREE_H
#define FIRST_LEVEL 3
#define SECOND_LEVEL 1

#include "TrustedArea.h"
#include "MainMemory.h"
#include "m_stdio.h"
#include <cassert>
#include <fstream>
using namespace std;

//
//MainMemory mainMemory;
//TrustedArea trustedArea;

int write_block(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,int block_index,unsigned char* buf,int size_to_write);
bool is_empty2(std::ifstream& pFile)
{
    return pFile.peek() == std::ifstream::traits_type::eof();
}
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
int power(int i){
    if(i==0) return 1;
    if(i==1) return 2;
    if(i==2) return 4;
    if(i==3) return 8;
    return 16;
}
int binaryToDec(int binaryNum){
    int sum=0;
    int k=0;
    while(binaryNum>0){
        int rem=binaryNum % 10;
        sum += rem*power(k);
        binaryNum/=10;
        k++;
    }
    return sum;
}
int get_level(int k){
    if(k==0){
        return FIRST_LEVEL;
    }
    return SECOND_LEVEL;
}

ReturnValue getRoot(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,unsigned char* result){
    int j=1;
    int k=0;
    for(int i = BLOCK_MAX_ADDR + 1; i<= HMAC_MAX_ADDR-2*HMAC_SIZE+1; i+= 2*HMAC_SIZE) {
        unsigned char* buf1=new unsigned char[HMAC_SIZE];
        unsigned char* buf2=new unsigned char[HMAC_SIZE];
        memset(buf1,0,HMAC_SIZE);
        memset(buf2,0,HMAC_SIZE);
        unsigned char* hmac1=cache->read_from_cache(TREE_HEIGHT,k);
        if(!hmac1){
            mainMemory->memread(i, buf1, HMAC_SIZE);
            cache->refer(TREE_HEIGHT,k,buf1);
            hmac1=buf1;
        }
        k++;
        unsigned char* hmac2=cache->read_from_cache(TREE_HEIGHT,k);
        if(!hmac2){
            mainMemory->memread(i+HMAC_SIZE, buf2, HMAC_SIZE);
            cache->refer(TREE_HEIGHT,k,buf2);
            hmac2=buf2;
        }
        k++;
        unsigned char tmp[2 * HMAC_SIZE];
        memset(tmp,0,2*HMAC_SIZE);
        m_strncpy(tmp,hmac1, HMAC_SIZE);
        m_strncat(tmp,HMAC_SIZE,hmac2, HMAC_SIZE);
        unsigned char hashed_data[SHA_LENGTH_BYTES];
        memset(hashed_data,0,SHA_LENGTH_BYTES);
        SHA256(tmp,sizeof(tmp), hashed_data);
        trustedArea->allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);
        delete[] buf1;
        delete[] buf2;
    }
    int n=0; //Que eso?
//    trustedArea->print();
    int height = TREE_HEIGHT;
    int index;
    while((n=trustedArea->get_number_of_tags())>1){
        --height;
        index = 0;
        for(int i=0; i<= n-2; i+=2){
            unsigned char sha2[2*SHA_LENGTH_BYTES];
            memset(sha2,0,2*SHA_LENGTH_BYTES);
            unsigned char* hmac3=trustedArea->get_tag();
            m_strncpy(sha2, hmac3,SHA_LENGTH_BYTES);
            cache->refer(height, index, hmac3);
            trustedArea->delete_tag();
            ++index;
            unsigned char* hmac4=trustedArea->get_tag();
            cache->refer(height,index,hmac4);
            m_strncat(sha2,SHA_LENGTH_BYTES,hmac4,SHA_LENGTH_BYTES);
            trustedArea->delete_tag();
            ++index;
            unsigned char hashed_data[SHA_LENGTH_BYTES];
            memset(hashed_data,0,SHA_LENGTH_BYTES);
            SHA256(sha2,sizeof(sha2), hashed_data);
            trustedArea->allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);
        }
    }
    m_strncpy(result,trustedArea->get_tag(),SHA_LENGTH_BYTES);
    trustedArea->delete_tag();

    return SUCCESS;

}


unsigned char* getDataPointer(MainMemory* mainMemory,LRUCache* cache,CacheKey node){
    unsigned char* buf = cache->is_in_cache(node.height,node.index);
    if(buf){
        cache->refer(node.height,node.index,buf);
        unsigned char* hmac = new unsigned char[HMAC_SIZE];
        m_strncpy(hmac,buf,HMAC_SIZE);
        return hmac;
    }
    if(node.height == TREE_HEIGHT){
        unsigned char* hmac=new unsigned char[HMAC_SIZE];
        memset(hmac,0,HMAC_SIZE);
        mainMemory->memread(hmac_addr(block_addr(node.index)),hmac,HMAC_SIZE);
        return hmac;
    }
    unsigned char* left_son_hmac = getDataPointer(mainMemory,cache, cache->getLeftSon(node.height,node.index));
    unsigned char* right_son_hmac = getDataPointer(mainMemory,cache,cache->getRightSon(node.height,node.index));
    assert(left_son_hmac && right_son_hmac);
    unsigned char tmp[2 * HMAC_SIZE];
    memset(tmp,0,2*HMAC_SIZE);
    m_strncpy(tmp,left_son_hmac, HMAC_SIZE);
    m_strncat(tmp,HMAC_SIZE,right_son_hmac, HMAC_SIZE);
    unsigned char* hashed_data=new unsigned char[SHA_LENGTH_BYTES];
    memset(hashed_data,0,SHA_LENGTH_BYTES);
    SHA256(tmp,sizeof(tmp), hashed_data);
    delete[] left_son_hmac;
    delete[] right_son_hmac;
    return hashed_data;
}
unsigned char* getRootLite(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,CacheKey node,unsigned char* hmac){
    if(node.height==0){
        return hmac;
    }
    assert(hmac);
    unsigned char* brother_hmac = getDataPointer(mainMemory,cache,cache->getBrother(node.height,node.index));
    CacheKey parent=cache->getParentIndex(node.height,node.index);
    unsigned char tmp[2 * HMAC_SIZE];
    memset(tmp,0,2*HMAC_SIZE);
    int m_side = cache->getSide(node.height,node.index);
    if(m_side==0){
        m_strncpy(tmp,hmac, HMAC_SIZE);
        m_strncat(tmp,HMAC_SIZE,brother_hmac, HMAC_SIZE);
    }
    else{
        m_strncpy(tmp,brother_hmac, HMAC_SIZE);
        m_strncat(tmp,HMAC_SIZE,hmac, HMAC_SIZE);
    }
    unsigned char* hashed_data=new unsigned char[SHA_LENGTH_BYTES];
    memset(hashed_data,0,SHA_LENGTH_BYTES);
    SHA256(tmp,sizeof(tmp), hashed_data);
    cache->refer(parent.height,parent.index,hashed_data);
    delete[] brother_hmac;
    delete[] hmac;
    return getRootLite(mainMemory,trustedArea,cache,parent,hashed_data);
}




/*FIXME: Memory leak
 * if height isn't TREE_HEIGHT then we got allocated block (by getDataPointer) that should be freed
 * but if it's the first run (i.e., height is TREE_HEIGHT) then the block is from our mainMemory which
 * means we can't delete it..
 * one possible solution is to allocate the first block run so we can free it in this function
 * */

bool verify_block_integrity(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,unsigned char* block,int height, int index){
    unsigned char* trusted_block = cache->is_in_cache(height,index);
    if(!trusted_block){
        CacheKey parent = cache->getParentIndex(height,index);
        //cache->refer(height,index,block);
        unsigned char* parent_data=getDataPointer(mainMemory,cache,parent);
        unsigned char* trusted_parent = cache->is_in_cache(parent.height, parent.index);
        if(trusted_parent){
            bool res=m_strncmp(parent_data,trusted_parent,HMAC_SIZE);
            delete[] parent_data;
            if(!res){
                return true;
            }
            return false;
        }
        else{
            delete[] block;
            return verify_block_integrity(mainMemory,trustedArea,cache,parent_data,parent.height, parent.index);
        }
    }
    else {
        // the Block is in Cache
        int res = m_strncmp(trusted_block, block, HMAC_SIZE);
        delete[] block;
        if (!res) {
            return true;
        }
        return false;
    }
}
bool verify_integrity(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache){
    unsigned char curr_root[SHA_LENGTH_BYTES];
    memset(curr_root,0,SHA_LENGTH_BYTES);
    getRoot(mainMemory,trustedArea,cache,curr_root);
    if(!m_strncmp(curr_root,(trustedArea->get_root()),SHA_LENGTH_BYTES)){
        return true;
    }
    //FIXME: FLUSH THE CACHE boy!!
    return false;
}
// Binary index of block 001 , status Invalid/Valid , Data
void write_to_log(int binaryIndex[],int status, unsigned char* data){
    ofstream mylog("log.txt",std::ofstream::app);
    mylog << status <<" ";
    for(int i=2;i>=0;i--){
        mylog<<binaryIndex[i];
    }

    mylog<<" "<< data << std::endl;
    mylog.close();
}
void parse_log(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache){
    std::ifstream input( "log.txt" );
    int x,y;
    input >> x >> y;
    int block_index=binaryToDec(y);
    unsigned char data_to_write[BLOCK_SIZE];
    memset(data_to_write,0,BLOCK_SIZE);
//    input >> data_to_write;
    input.get();
    input.getline((char*)data_to_write,BLOCK_SIZE);
    //std::cout<<"Here I'm parsing the log " << x <<" ---" <<y <<"\n";
    write_block(mainMemory,trustedArea,cache,block_index,data_to_write,BLOCK_SIZE);
}
void erase_log(){
    std::ofstream ofs;
    ofs.open("log.txt", std::ofstream::out | std::ofstream::trunc);
    ofs.close();
}

int read_block_by_addr(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,uint64_t addr,unsigned char* buf){
    int index = block_id(addr);
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
    unsigned char *alloc_hmac = new unsigned char[HMAC_SIZE];
    memset(alloc_hmac,0,HMAC_SIZE);
    m_strncpy(alloc_hmac,hmac,HMAC_SIZE);
    bool res=verify_block_integrity(mainMemory,trustedArea,cache,alloc_hmac,TREE_HEIGHT,block_id(addr));
    //at this point, alloc_hmac is freed by verify_block_integrity!
    if(!res){
        return -1; //Not verifiable
    }
    unsigned char aad[256]="";
    int read_size = gcm_decrypt(tmp_buf,BLOCK_SIZE,aad,256,hmac,key,nonce,NONCE_SIZE,buf);
    return read_size;                          // How many bytes we actually decrypted and read
}
int read_block(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,int block_index,unsigned char* buf){
    uint64_t addr=block_index*BLOCK_SIZE;
    int read_size=read_block_by_addr(mainMemory,trustedArea,cache,addr,buf);
    return read_size;
}
int write_block_aux(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,int block_index,unsigned char* buf,int size_to_write){
    unsigned char* hmac;
    uint64_t addr= block_index*BLOCK_SIZE;
    uint64_t nonce_address=nonce_addr(addr);
    uint64_t hmac_address=hmac_addr(addr);
    hmac=mainMemory->getMemoryAddress(hmac_address);
    unsigned char *alloc_hmac = new unsigned char[HMAC_SIZE];
    memset(alloc_hmac,0,HMAC_SIZE);
    m_strncpy(alloc_hmac,hmac,HMAC_SIZE);
//    auto start = std::chrono::high_resolution_clock::now();
    bool res=verify_block_integrity(mainMemory,trustedArea,cache,alloc_hmac,TREE_HEIGHT,block_index);
//    auto end = std::chrono::high_resolution_clock::now();
//    auto finish = end-start;
//    std::cout << "Verify block integrity time: " << finish.count()  << std::endl;
    //at this point, alloc_hmac is freed by verify_block_integrity!
    if(!res){
        return -1; //Not verifiable
    }
    int binaryNum[32];
    decToBinary(block_index,binaryNum);
    write_to_log(binaryNum,0,buf);
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
//    cache->flush();
    mainMemory->memwrite(nonce_address,new_nonce,NONCE_SIZE);
    trustedArea->update_key(block_index+1,new_key);
    cache->update_cache(TREE_HEIGHT,block_index,new_tag);
    unsigned char* new_root;
//    start = std::chrono::high_resolution_clock::now();
//    getRoot(mainMemory,trustedArea,cache,new_root);
    CacheKey m_key=CacheKey(TREE_HEIGHT,block_index);
    alloc_hmac = new unsigned char[HMAC_SIZE];
    memset(alloc_hmac,0,HMAC_SIZE);
    m_strncpy(alloc_hmac,new_tag,HMAC_SIZE);
    new_root=getRootLite(mainMemory,trustedArea,cache,m_key,alloc_hmac);
//    end  = std::chrono::high_resolution_clock::now();
//    finish = end - start;
//    std::cout << "get root lite time: " << finish.count()  << std::endl;
    trustedArea->update_root(new_root);
    erase_log();
    delete[] new_key;
    delete[] new_nonce;
    return 0;
}
int write_block(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,int block_index,unsigned char* buf,int size_to_write){
    int res=write_block_aux(mainMemory,trustedArea,cache,block_index,buf,size_to_write);
    if(res==-1){
        return res;
    }
    std::ifstream file("log.txt");
    if(!is_empty2(file)){
        //Crash happened!! Need to re-write the block.
        std::cout<<"CRAAAAAAAAAAAAAAAAAAAAAAAAAASH --- PARSING SOS... \n\n";
        parse_log(mainMemory,trustedArea,cache);
    }
    return 0;
}
void printToFile(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache){
    std::ofstream ofs;
    ofs.open("memory.txt", std::ofstream::out | std::ofstream::trunc);
    ofs.close();
    ofstream memFile("memory.txt",std::ofstream::app);
    memFile << "Printing Memory : \n";
    for(int i=0;i<NUM_OF_BLOCKS ;i++){
        unsigned char* data=new unsigned char[BLOCK_SIZE];
        read_block(mainMemory,trustedArea,cache,i,data);
        memFile << data << "\n";
        delete[] data;
    }
//    memFile<< " " << std::endl;
    memFile.close();
}


#endif //INTEGRITYTREE_INTEGRITYTREE_H