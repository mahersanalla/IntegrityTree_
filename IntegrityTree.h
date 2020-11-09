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

//        int* hmac1_virtual_addr=cache->getMapping(k+OFFSET);
        unsigned char* hmac1=cache->read_from_cache(TREE_HEIGHT,k);
        if(!hmac1){
            mainMemory->memread(i, buf1, HMAC_SIZE);
            cache->refer(TREE_HEIGHT,k,buf1);
            hmac1=buf1;
        }
//        cache->fillPointersArray(k+OFFSET,hmac1);
//        std::cout<<"Hmac is: "<<hmac1<<std::endl;
        k++;
//        int* hmac2_virtual_addr=cache->getMapping(k+OFFSET);
        unsigned char* hmac2=cache->read_from_cache(TREE_HEIGHT,k);
        if(!hmac2){
            mainMemory->memread(i+HMAC_SIZE, buf2, HMAC_SIZE);
            cache->refer(TREE_HEIGHT,k,buf2);
            hmac2=buf2;
        }
//        std::cout<<"Hmac is: "<<hmac2<<std::endl;
//        cache->fillPointersArray(k+OFFSET,hmac2);
        k++;
        unsigned char tmp[2 * HMAC_SIZE];
        memset(tmp,0,2*HMAC_SIZE);
        m_strncpy(tmp,hmac1, HMAC_SIZE);
        m_strncat(tmp,HMAC_SIZE,hmac2, HMAC_SIZE);
        unsigned char hashed_data[SHA_LENGTH_BYTES];
        memset(hashed_data,0,SHA_LENGTH_BYTES);
        SHA256(tmp,sizeof(tmp), hashed_data);
        trustedArea->allocate_in_trusted_memory(hashed_data,sizeof(hashed_data),true);
//        delete[] buf1;
//        delete[] buf2;
    }
    int n=0; //Que eso?
//    trustedArea->print();
    int height = TREE_HEIGHT;
    while((n=trustedArea->get_number_of_tags())>1){
        --height;
        int index = 0;
        for(int i=0; i<= n-2; i+=2){
            unsigned char sha2[2*SHA_LENGTH_BYTES];
            memset(sha2,0,2*SHA_LENGTH_BYTES);
            m_strncpy(sha2, trustedArea->get_tag(),SHA_LENGTH_BYTES);
//            int* hmac3_virtual_addr=cache->getMapping(k);
            unsigned char* hmac3=trustedArea->get_tag();
            cache->refer(height, index, hmac3);
//            cache->fillPointersArray(k,hmac3);
            trustedArea->delete_tag();
            ++index;
//            int* hmac4_virtual_address=cache->getMapping(k);
            unsigned char* hmac4=trustedArea->get_tag();
//            cache->fillPointersArray(k,hmac4);
            cache->refer(height,index,hmac4);
            m_strncat(sha2,SHA_LENGTH_BYTES,trustedArea->get_tag(),SHA_LENGTH_BYTES);
            trustedArea->delete_tag();
            ++index;
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


unsigned char* getDataPointer(MainMemory* mainMemory,LRUCache* cache,CacheKey node){
    unsigned char* buf = cache->is_in_cache(node.height,node.index);
    if(node.height == TREE_HEIGHT || buf!=NULL){
        if(!buf){
            //unsigned char* data = new unsigned char[HMAC_SIZE];
            unsigned char data[HMAC_SIZE];
            memset(data,0,HMAC_SIZE);
            mainMemory->memread(hmac_addr(block_addr(node.index)),data,HMAC_SIZE);
            return data;
        }
        return buf;
    }
    unsigned char* left_son_hmac = getDataPointer(mainMemory,cache, cache->getLeftSon(node.height,node.index));
    unsigned char* right_son_hmac = getDataPointer(mainMemory,cache,cache->getLeftSon(node.height,node.index));
    unsigned char tmp[2 * HMAC_SIZE];
    memset(tmp,0,2*HMAC_SIZE);
    m_strncpy(tmp,left_son_hmac, HMAC_SIZE);
    m_strncat(tmp,HMAC_SIZE,right_son_hmac, HMAC_SIZE);
    unsigned char hashed_data[SHA_LENGTH_BYTES];
    memset(hashed_data,0,SHA_LENGTH_BYTES);
    SHA256(tmp,sizeof(tmp), hashed_data);
    return hashed_data;
}




//FIXME: Nothing
bool verify_block_integrity(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,unsigned char* block,int height, int index){
//    int* virtual_block_addr=cache->getMapping(block_index);
    unsigned char* trusted_block = cache->is_in_cache(height,index);
    if(!trusted_block){
        CacheKey parent = cache->getParentIndex(height,index);
//        int* parent_addr=cache->getMapping(parent);
        unsigned char* parent_data=getDataPointer(mainMemory,cache,parent); // returns tag of parent
        unsigned char* trusted_parent = cache->is_in_cache(parent.height, parent.index);
        CacheKey son1=cache->getRightSon(parent.height,parent.index);
        CacheKey son2=cache->getLeftSon(parent.height,parent.index);
        CacheKey other_son = (index==son1.index && height == son1.height) ? son2 : son1;
//        int* other_addr=cache->getMapping(other_son);
        unsigned char* other_son_data=getDataPointer(mainMemory,cache,other_son);
        //mainMemory->memread(other_addr,other_son_data,HMAC_SIZE);   //FIXME
        unsigned char tmp[2 * HMAC_SIZE];
        memset(tmp,0,2*HMAC_SIZE);
        if(other_son.index < index){
            m_strncpy(tmp,other_son_data, HMAC_SIZE);
            m_strncat(tmp,HMAC_SIZE,block, HMAC_SIZE);
        }
        else{
            m_strncpy(tmp,block, HMAC_SIZE);
            m_strncat(tmp,HMAC_SIZE,other_son_data, HMAC_SIZE);
        }
        unsigned char hashed_data[SHA_LENGTH_BYTES];
        memset(hashed_data,0,SHA_LENGTH_BYTES);
        SHA256(tmp,sizeof(tmp), hashed_data);
        if(trusted_parent){
            bool res=m_strncmp(hashed_data,trusted_parent,HMAC_SIZE);
            if(!res){
                return true;
            }
            return false;
        }
        else{
            return verify_block_integrity(mainMemory,trustedArea,cache,hashed_data,parent.height, parent.index);
        }
    }
    else {
        // the Block is in Cache
        int res = m_strncmp(trusted_block, block, HMAC_SIZE);
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
//        std::cout<<"\n\nTHE TREE IS VALID---\n";
        return true;
    }
//    std::cout<<"THE TREE IS FUCKED:( LEAVE AND THROW THE PC NOWWWW!\n\n\n\n";
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
//    if(!verify_integrity(mainMemory,trustedArea,cache)){
//        return -1;
//    }
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
   // FIXME:
    bool res=verify_block_integrity(mainMemory,trustedArea,cache,hmac,TREE_HEIGHT,block_id(addr));
    if(!res){
        return -1; //Not verifiable
    }
//    std::cout<<"Hereeee I'm\n";
    unsigned char aad[256]="";
    int read_size = gcm_decrypt(tmp_buf,BLOCK_SIZE,aad,256,hmac,key,nonce,NONCE_SIZE,buf);
    return read_size;                          // How many bytes we actually decrypted and read
}
int read_block(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,int block_index,unsigned char* buf){
   // chrono::time_point start;
    //start = std::chrono::high_resolution_clock::now();
    uint64_t addr=block_index*BLOCK_SIZE;
    int read_size=read_block_by_addr(mainMemory,trustedArea,cache,addr,buf);
    //auto finish = std::chrono::high_resolution_clock::now();
    //std::chrono::duration<double> elapsed = finish - start;
//    std::cout<<"Elapsed Time of Read Block without Integrity is : " << elapsed.count()<<std::endl;
    return read_size;
}
int write_block_aux(MainMemory* mainMemory,TrustedArea* trustedArea,LRUCache* cache,int block_index,unsigned char* buf,int size_to_write){
    //chrono::time_point start;
    //start = std::chrono::high_resolution_clock::now();
    if(!verify_integrity(mainMemory,trustedArea,cache)){
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
    //cache->write_to_cache(hmac_address,new_tag); //FIXME
    cache->flush();
    mainMemory->memwrite(nonce_address,new_nonce,NONCE_SIZE);
    trustedArea->update_key(block_index+1,new_key);
    unsigned char new_root[SHA_LENGTH_BYTES];
    getRoot(mainMemory,trustedArea,cache,new_root);
    trustedArea->update_root(new_root);
    erase_log();
    delete[] new_key;
    delete[] new_nonce;
   // auto finish = std::chrono::high_resolution_clock::now();
    //std::chrono::duration<double> elapsed = finish - start;
//    std::cout<<"Elapsed Time of Write Block with Integrity is : " << elapsed.count()<<std::endl;
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